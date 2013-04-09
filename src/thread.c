/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2013 All Rights Reserved
************************************************************
 Thread Management code
***********************************************************/

#include "sixxsd.h"

const char module_thread[] = "thread";
#define module module_thread

/* Debugging */
/* #define DD(x) {} */
#define DD(x) x

const char *ts_names[20] = {
	"dying",
	"running",
	"sleeping",
	"selectwait",
	"ioread"
};

/* Get & Lock current thread handle */
static struct sixxsd_thread *thread_getbyid(os_thread_id thread_id);
static struct sixxsd_thread *thread_getbyid(os_thread_id thread_id)
{
	struct sixxsd_thread	*t = NULL;

	if (!g_conf || !g_conf->threads) return NULL;

	rwl_lockR(&g_conf->rwl_threads);

	if (g_conf->threads)
	{
		/* Walk through the list */
		for (t = g_conf->threads; t && t->thread_id != thread_id; t = t->next);

		/* Really found? */
		if (t && t->thread_id == thread_id) mutex_lock(t->mutex);
		else t = NULL;
	}

	/* Release the global thread list lock */
	rwl_releaseR(&g_conf->rwl_threads);

	return t;
}

struct sixxsd_thread *thread_getthis(VOID)
{
	return thread_getbyid(os_getthisthreadid());
}

/*
 * Remove a thread from the thread list
 * This is automatically called by the threading
 * code when it returns from the calling function
*/
VOID thread_remove(struct sixxsd_thread *thread, BOOL dolock)
{
	struct sixxsd_thread *tt = NULL, *t = NULL;

	if (!thread) return;

	if (!g_conf)
	{
		mddolog("Configuration was already gone before remove thread\n");
		mfree(t, "thread", sizeof(*t));
		return;
	}

	if (dolock) rwl_lockW(&g_conf->rwl_threads);

	if (g_conf->threads)
	{
		if (g_conf->threads->thread_id == thread->thread_id)
		{
			t = g_conf->threads;
			g_conf->threads = t->next;
		}
		else
		{
			for (	tt = g_conf->threads, t = tt->next;
				t && t->thread_id != thread->thread_id;
				tt=t, t = t->next);

			if (t && t->thread_id == thread->thread_id)
			{
				tt->next = t->next;
			}
			else
			{
				t = NULL;
			}
		}
	}

	if (t && t->thread_id == thread->thread_id)
	{
		mddolog("Thread %s stopped\n", t->description ? t->description : "<no description>");
		if (t->description) mfree(t->description, "strdup", strlen(t->description));
		if (t->notice) mfree(t->notice, "strdup", strlen(t->notice));
		pthread_cond_destroy(&t->cond);
		mutex_destroy(t->mutex);
		mfree(t, "thread", sizeof(*t));
	}
	else mdolog(LOG_WARNING, "Thread not found\n");

	if (dolock) rwl_releaseW(&g_conf->rwl_threads);
}

BOOL thread_setnotice(const char *notice)
{
	struct sixxsd_thread *t;

	t = thread_getthis();
	if (!t) return false;

	if (t->notice) mfree(t->notice, strlen(notice), "strdup");

	if (notice) t->notice = mstrdup(notice);
	else t->notice = NULL;

	return true;
}

BOOL thread_setstate(enum thread_states state)
{
	struct sixxsd_thread *t;

	t = thread_getthis();
	if (!t) return false;

	t->state = state;

	return true;
}

/* Let the thread sleep for X seconds + Y nsecs, but allow it to be breaked for exit */
BOOL thread_sleep(unsigned int seconds, unsigned int nseconds)
{
	struct sixxsd_thread	*t = NULL;
	struct timespec		timeout;
	struct timeval		now;
	int			rc;

	t = thread_getthis();

	/* Nothing we can do, return with failure so that it will abort */
	if (!t)
	{
		/* mdolog(LOG_ERR, "Couldn't find my thread while trying to sleep!\n"); */
		return false;
	}

	/* get current time */ 
	gettimeofday(&now, NULL);
	timeout.tv_sec = now.tv_sec + seconds;
	timeout.tv_nsec = (now.tv_usec * 1000) + nseconds;

	mutex_lock(t->mutex);

	t->state = thread_state_sleeping;
	rc = pthread_cond_timedwait(&t->cond, &t->mutex, &timeout);
	t->state = thread_state_running;

	/* Unlock the thread mutex */
	mutex_release(t->mutex);

#ifdef DEBUG
	if (rc != ETIMEDOUT && rc != 0)
	{
		mdolog(LOG_ERR, "pthread_cond_timedwait(%u, %u) on %s (%s) returned %u\n", seconds, nseconds, t->description ? t->description : "<no description>", t->notice ? t->notice : "", rc);
	}
#endif

	return (rc == ETIMEDOUT ? true : false);
}

static VOID *thread_autoremove(VOID *arg);
static VOID *thread_autoremove(VOID *arg)
{
	struct sixxsd_thread	*t =(struct sixxsd_thread *)arg;

	/* Mask out all signals (main will handle this) */
	sigset_t	mask;
	int		rc;

	sigfillset(&mask);
	rc = pthread_sigmask(SIG_BLOCK, &mask, NULL);
	if (rc != 0) mdolog(LOG_ERR, "pthread_sigmask() returned %d\n", rc);

	t->start_routine(t->arg);
	thread_remove(t, true);
	return NULL;
}

os_thread_id thread_add(struct sixxsd_context *ctx, const char *description, PTR *(*start_routine)(PTR *), PTR *arg, struct sixxsd_thread **store, BOOL cancelable)
{
	struct sixxsd_thread	*t, *tt;
	os_thread_id		id;

	/* Allocate a new thread structure */
	t = (struct sixxsd_thread *)mcalloc(sizeof(struct sixxsd_thread), "thread");
	if (!t)
	{
		ctx_printef(ctx, errno, "[%s] Couldn't allocate memory for a new thread... aborting\n", description);
		return 0;
	}

	t->description = mstrdup(description);
	t->notice = NULL;
	t->start_routine = start_routine;
	t->arg = (arg ? arg : (PTR *)g_conf);
	t->state = thread_state_running;
	t->cancelable = cancelable;
	mutex_init(t->mutex);

	/* Store the thread pointer in the user provided spot,
	 * this makes sure that that pointer is there before
	 * the thread is created
	*/
	if (store) *store = t;

	/*
	 * Lock here so that we add the thread before
	 * it has to chance to remove itself again ;)
	*/
	rwl_lockW(&g_conf->rwl_threads);

	/* Create the thread if needed (only the 'main' thread should not do this) */
	if (start_routine)
	{
		pthread_cond_init(&t->cond, NULL);
		if (0 != pthread_create(&t->thread, NULL, thread_autoremove, t))
		{
			ctx_printef(ctx, errno, "[%s] Couldn't create thread... aborting\n", description);

			rwl_releaseW(&g_conf->rwl_threads);

			/* Don't forget to free the thread structure memory */
			mfree(t, "thread", sizeof(*t));

			return 0;
		}

		t->thread_id = (os_thread_id)t->thread;

		/* Detach the thread */
		pthread_detach(t->thread);
	}
	else
	{
		/* Tricky: this is the 'main' thread */
		t->thread_id =  os_getthisthreadid();
	}

	t->starttime = gettime();

	/* Add it to the list */
	if (!g_conf->threads) g_conf->threads = t;
	else
	{
		for (tt = g_conf->threads; tt->next; tt = tt->next);
		tt->next = t;
	}

	id = t->thread_id;

	DD(mddolog("Thread %s started\n", t->description);)

	rwl_releaseW(&g_conf->rwl_threads);

	return id;
}

VOID thread_exit(VOID)
{
	unsigned		int i = 0;
	BOOL			done = false;
	struct sixxsd_thread	*t, *n;
	os_thread_id		tid = os_getthisthreadid();

	if (!g_conf) return;

	assert(!g_conf->running);

	mddolog("Signalling thread that they should exit\n");

	rwl_lockR(&g_conf->rwl_threads);

	for (t = g_conf->threads; g_conf && t; t = t->next)
	{
		if (t->thread_id == tid) continue;

		if (t->cancelable) pthread_kill(t->thread, SIGINT);
		else pthread_cond_broadcast(&t->cond);
	}

	rwl_releaseR(&g_conf->rwl_threads);

	/* Make sure that all threads have ended */
	while (i < 20 && !done && g_conf)
	{
		done = true;

		/* Sleep a bit if there is something in the list */
		if (g_conf && g_conf->threads)
		{
			if (!g_conf) break;

			rwl_lockW(&g_conf->rwl_threads);

			for (t = g_conf->threads; g_conf && t; t = t->next)
			{
				if (t->thread_id == tid || t->cancelable) continue;

				mddolog("Still waiting for '%s%s%s%s' [%s]%s to finish...\n",
					t->description,
					t->notice ? " (" : "",
					t->notice ? t->notice : "",
					t->notice ? ")" : "",
					ts_names[t->state],
					t->state != thread_state_running ? " .oO(zzZzzZzzz)" : "");
				pthread_cond_signal(&t->cond);
				done = false;
			}

			rwl_releaseW(&g_conf->rwl_threads);
		}

		if (!done)
		{
			mddolog("Threads Exiting - waiting for some threads to exit\n");
			sleep(5);
		}

		i++;
	}

	if (g_conf->threads)
	{
		rwl_lockW(&g_conf->rwl_threads);

		for (t = g_conf->threads; g_conf && t; t = n)
		{
			n = t->next;
			if (!t->cancelable) mdolog(LOG_WARNING, " Was still running: \"%s\" [%s]\n", t->description, ts_names[t->state]);
			pthread_cancel(t->thread);
			thread_remove(t, false);
		}

		rwl_releaseW(&g_conf->rwl_threads);
	}

	mddolog("Threads Exiting - done\n");
}

int thread_list(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[])
{
	struct sixxsd_thread	*t = NULL;
	os_thread_id		thread_id = os_getthisthreadid();
	struct tm		teem;
	uint64_t		now = gettime();
	unsigned int		cnt = 0;
	time_t			tee;

	rwl_lockR(&g_conf->rwl_threads);

	for (t = g_conf->threads; t; t = t->next)
	{
		tee = (time_t)t->starttime;
		localtime_r(&tee, &teem);

		ctx_printdf(ctx,
				"0x%" PRIx64 " %4u-%02u-%02u %02u:%02u:%02u (%4" PRIu64 " seconds) : %s%s%s%s%s [%s]%s\n",
#ifdef _64BIT
				(uint64_t)t->thread_id,
#else
				(uint64_t)t->thread_id,
#endif
				teem.tm_year+1900, teem.tm_mon+1, teem.tm_mday,
				teem.tm_hour, teem.tm_min, teem.tm_sec, now - t->starttime,
				t->description ? t->description : "<no description>",
				t->notice ? " (" : "", t->notice ? t->notice : "", t->notice ? ")" : "",
				os_thread_equal(t->thread_id, thread_id) ? " (this)" : "",
				ts_names[t->state],
				t->state != thread_state_running ? " .oO(zzZzzZzzz)" : "");
	}

	rwl_releaseR(&g_conf->rwl_threads);

	if (cnt == 0)
	{
		ctx_printf(ctx, "No running threads found\n");
		return 300;
	}

	return 200;
}

