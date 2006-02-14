/**************************************
 SixXSd - SixXS PoP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
***************************************
 $Author: jeroen $
 $Id: thread.c,v 1.4 2006-02-14 15:41:36 jeroen Exp $
 $Date: 2006-02-14 15:41:36 $

 SixXSd Thread Management 
**************************************/

const char module_thread[] = "thread";
#define module module_thread

#include "sixxsd.h"

/*
 * Remove a thread from the thread list
 * This is automatically called by the threading
 * code when it returns from the calling function
 * It is also called by thread_end();
 */
void thread_remove(struct sixxs_thread *thread);
void thread_remove(struct sixxs_thread *thread)
{
	struct sixxs_thread *tt = NULL, *t = NULL;

	OS_Mutex_Lock(&g_conf->mutex_thread, "thread_remove");

	if (g_conf->threads && g_conf->threads->thread_id == thread->thread_id)
	{
		t = g_conf->threads;
		g_conf->threads = t->next;
	}
	else
	{
		for (tt = g_conf->threads, t = tt->next; t && t->thread_id != thread->thread_id; tt=t, t = t->next);
		if (t && t->thread_id == thread->thread_id)
		{
			tt->next = t->next;
		}
		else t = NULL;
	}

	if (t && t->thread_id == thread->thread_id)
	{
		mddolog("Thread 0x%x (%s) stopped\n", t->thread, t->description);
		free(t->description);
		t->description = NULL;
		free(t);
	}
	else mdolog(LOG_WARNING, "Thread 0x%x not found\n", thread);

	OS_Mutex_Release(&g_conf->mutex_thread, "thread_remove");
}

#ifndef _WIN32
void *thread_autoremove(void *arg);
void *thread_autoremove(void *arg)
#else
DWORD WINAPI thread_autoremove(LPVOID arg);
DWORD WINAPI thread_autoremove(LPVOID arg)
#endif

{
	struct sixxs_thread *t =(struct sixxs_thread *)arg;
	
	t->start_routine(t->arg);
	thread_remove(t);
#ifndef _WIN32
	return NULL;
#else
	return 0;
#endif
}

void thread_add(const char *description, void *(*start_routine)(void *), void *arg, bool detach)
{
	struct sixxs_thread	*t;

	/* Allocate a new thread structure */
	t = malloc(sizeof(struct sixxs_thread));
	if (!t)
	{
		mdolog(LOG_ERR, "[%s] Couldn't allocate memory for a new thread... aborting\n", description);
		exit(-1);
	}

	/* Clear the memory */
	memset(t, 0, sizeof(*t));

	t->description = strdup(description);
	t->start_routine = start_routine;
	t->arg = (arg ? arg : (void *)g_conf);

	/* Lock here so that we add the thread before */
	/* it has to chance to remove itself again ;) */
	OS_Mutex_Lock(&g_conf->mutex_thread, "thread_add");

	/* Create the thread */
#ifndef _WIN32
	if (0 != pthread_create(&t->thread, NULL, thread_autoremove, t))
#else
	if ((t->thread = CreateThread(NULL, 0, thread_autoremove, t, 0, &t->thread_id)) == NULL)
#endif
	{
		mdolog(LOG_ERR, "[%s] Couldn't create thread... aborting\n", description);
		exit(-1);
	}

	/* Add it to the list */
	if (!g_conf->threads) g_conf->threads = t;
	else
	{
		t->next = g_conf->threads;
		g_conf->threads = t;
	}

	mddolog("Thread 0x%x (%s) started\n", t->thread, t->description);

	OS_Mutex_Release(&g_conf->mutex_thread, "thread_add");

#ifndef _WIN32
	t->thread_id = t->thread;

	/* Detach the thread */
	if (detach) pthread_detach(t->thread);
#endif
}

void thread_cleanup(void)
{
	struct sixxs_thread *t;
	unsigned int loops = 0;

	while (g_conf->threads)
	{
		sleep(5);
		OS_Mutex_Lock(&g_conf->mutex_thread, "thread_cleanup");
		for (t = g_conf->threads; t; t = t->next)
		{
			mddolog("[%p] '%s' is still running\n", (void *)t, t->description);
		}
		OS_Mutex_Release(&g_conf->mutex_thread, "thread_cleanup");

		loops++;
		if (loops > 2) break;
	}
}

