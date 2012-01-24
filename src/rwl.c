/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2012 All Rights Reserved
************************************************************
 Read/Write Lock
***********************************************************/

#include "sixxsd.h"

const char module_rwl[] = "rwl";
#define module module_rwl

VOID rwl_init(rwl *l)
{
	assert(l);
	memzero(l, sizeof(*l));
	mutex_init(l->mutex);
	mutex_init(l->mutexW);
	l->readers = 0;
	l->writers = 0;
}

VOID rwl_destroy(rwl *l)
{
#ifdef DEBUG_LOCKS
	unsigned int	i, c = 0;
	char		buf[2048];
#endif

	assert(l);

#ifdef DEBUG_LOCKS
	for (i=0; i < lengthof(l->locks); i++)
	{
		if (l->locks[i].thread_id == 0) continue;

		format_stacktrace(buf, sizeof(buf), l->locks[i].trace, l->locks[i].trace_size);

		fflush(stdout);
		fprintf(stderr, "Thread 0x%p is still locking this RWL at destroy time\n", (VOID *)l->locks[i].thread_id);
		fprintf(stderr, "8<----------------------\n%s----------------->8", buf);
		fflush(stderr);
		c++;
	}

	if (c > 0) assert(false);
#endif

	assert(l->readers == 0);
	assert(l->writers == 0);

	mutex_destroy(l->mutex);
	mutex_destroy(l->mutexW);
}

#ifdef DEBUG_LOCKS
static VOID rwl_lock(rwl *l, BOOL add, BOOL reader);
static VOID rwl_lock(rwl *l, BOOL add, BOOL reader)
{
	unsigned int	i, k = (lengthof(l->locks) + 128);
	os_thread_id	tid;
	char		buf[2048];

	/* Ignore thread locks */
	if (&g_conf->rwl_threads == l) return;

	tid = os_getthisthreadid();

	for (i=0; i < lengthof(l->locks); i++)
	{
		if (l->locks[i].thread_id == 0 && k == (lengthof(l->locks)+128)) k = i;
		if (l->locks[i].thread_id != tid) continue;

		/* Thread is already locking this RWL */
		if (add)
		{
			if (reader)
			{
				if (l->locks[i].writers == 0)
				{
					l->locks[i].readers++;
					return;
				}
			}
			else
			{
				if (l->locks[i].readers == 0 && l->locks[i].writers == 0)
				{
					l->locks[i].writers++;
					return;
				}
			}

			format_stacktrace(buf, sizeof(buf), l->locks[i].trace, l->locks[i].trace_size);

			fflush(stdout);
			fprintf(stderr, "Thread 0x%p is already locking this RWL (readers=%" PRIu64 ", writers=%" PRIu64 ")\n", (VOID *)tid, l->locks[i].readers, l->locks[i].writers);
			fprintf(stderr, "8<-------------------\n%s---------------->8\n", buf);

			fprintf(stderr, "Current stacktrace:\n");
			output_stacktrace();
			fflush(stderr);

			assert(false);
		}
		else
		{
			if (reader)
			{
				if (l->locks[i].readers > 1)
				{
					l->locks[i].readers--;
					return;
				}
			}
			else if (l->locks[i].writers > 1)
			{
				l->locks[i].writers--;
				return;
			}

			/* Remove it */
			l->locks[i].thread_id = 0;
			l->locks[i].writers = l->locks[i].readers = 0;
			return;
		}
	}

	if (add)
	{
		if (k == (lengthof(l->locks)+128))
		{
			fflush(stdout);
			fprintf(stderr, "No locking slot left for locking RWL by Thread 0x%p\n", (VOID *)tid);
			output_stacktrace();
			assert(false);
		}

		/* Record this lock */
		l->locks[k].thread_id = tid;
		if (reader) l->locks[k].readers++;
		else l->locks[k].writers++;
		l->locks[k].trace_size = lengthof(l->locks[k].trace);
		dump_stacktrace(l->locks[k].trace, &l->locks[k].trace_size, 0);
	}
	else
	{
		fflush(stdout);
		fprintf(stderr, "Thread 0x%p was not locking this RWL\n", (VOID *)tid);
		output_stacktrace();
		fflush(stderr);
		assert(false);
	}
}
#else
#define rwl_lock(a,b,c) {}
#endif

VOID rwl_lockR(rwl *l)
{
	assert(l);

	mutex_lock(l->mutex);

	/* Let me read! */
	l->readers++;

	/* Release the readers/writers lock */
	mutex_release(l->mutex);

	/* Any waiting writers? Then wait for them to finish */
	if (l->writers > 0)
	{
		/* Try to get the Write Lock */
		mutex_lock(l->mutexW);

		/* Release it, because readers > 0 it won't be grabbed fully by a writer */
		mutex_release(l->mutexW);
	}

	rwl_lock(l, true, true);
}

VOID rwl_releaseR(rwl *l)
{
	assert(l);
	assert(l->readers > 0);

	/* One less reader */
	mutex_lock(l->mutex);

	l->readers--;
	rwl_lock(l, false, true);

	mutex_release(l->mutex);
}

VOID rwl_lockW(rwl *l)
{
	BOOL		w = false;
#ifdef DEBUG_LOCKS
	unsigned int	i;
	char		buf[2048];
#endif

	assert(l);

	mutex_lock(l->mutex);

	/* Let me write! */
	l->writers++;
	rwl_lock(l, true, false);

	/* Try to get the write lock */
	if (mutex_trylock(l->mutexW) == 0) w = true;

	/* Is something reading? */
	while (l->readers > 0 || !w)
	{
		/* Give it back */
		mutex_release(l->mutex);

		/* Release it for a bit */
		if (w)
		{
			mutex_release(l->mutexW);
			w = false;
		}

		/* Force a context switch */
#ifdef DEBUG_LOCKS
		/* Ignore thread locks */
		if (&g_conf->rwl_threads != l)
		{
			fflush(stdout);
			fprintf(stderr, "YIELDING for lock %p (%u,%u)\n", (VOID *)l, l->readers, l->writers);
			for (i=0; i < lengthof(l->locks); i++)
			{
				if (l->locks[i].thread_id == 0) continue;

				format_stacktrace(buf, sizeof(buf), l->locks[i].trace, l->locks[i].trace_size);
	
				fprintf(stderr, "Thread 0x%p is still locking this RWL at yield time\n", (VOID *)l->locks[i].thread_id);
				fprintf(stderr, "%s", buf);
				fflush(stderr);
			}
			fprintf(stderr, "== this thread: ==\n");
			output_stacktrace();
			fprintf(stderr, "== eoyl ==\n");
		}
#endif
		sched_yield();
		/* usleep(0); */

		/* Grab it again */
		mutex_lock(l->mutex);

		/* Try to get the write lock */
		if (mutex_trylock(l->mutexW) == 0) w = true;
	}

	mutex_release(l->mutex);
}

VOID rwl_releaseW(rwl *l)
{
	assert(l);
	assert(l->writers > 0);

	/* Acquire the readers/writers lock */
	mutex_lock(l->mutex);

	/* One less writer */
	l->writers--;
	rwl_lock(l, false, false);

	/* Unlock the write lock*/
	mutex_release(l->mutexW);

	/* Release */
	mutex_release(l->mutex);
}

