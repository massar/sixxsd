/**************************************
 SixXSd - SixXS POP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
***************************************
 $Author: jeroen $
 $Id: thread.c,v 1.1 2004-08-30 19:33:45 jeroen Exp $
 $Date: 2004-08-30 19:33:45 $

 SixXSd Thread Management 
**************************************/

#include "sixxsd.h"

// Remove itself from the thread list
void thread_remove()
{
	struct sixxs_thread *tt = NULL, *t = NULL;
	pthread_t thread = pthread_self();

	pthread_mutex_lock(&g_conf->mutex);

	if (g_conf->threads && g_conf->threads->thread == thread)
	{
		t = g_conf->threads;
		g_conf->threads = t->next;
	}
	else
	{
		for (tt = g_conf->threads, t = tt->next; t && t->thread != thread; tt=t, t = t->next);
		if (t && t->thread == thread)
		{
			tt->next = t->next;
		}
		else t = NULL;
	}

	if (t && t->thread == thread)
	{
		D(dolog(LOG_DEBUG, "Thread 0x%x (%s) stopped\n", t->thread, t->description));
		free(t->description);
		free(t);
	}
	else dolog(LOG_WARNING, "Thread 0x%x not found\n", thread);

	pthread_mutex_unlock(&g_conf->mutex);
}

void *thread_autoremove(void *arg)
{
	struct sixxs_thread *t =(struct sixxs_thread *)arg;
	
	t->start_routine(t->arg);
	thread_remove();
	return NULL;
}

void thread_add(char *description, void *(*start_routine)(void *), void *arg)
{
	struct sixxs_thread	*t, *tt;

	// Allocate a new thread structure
	t = malloc(sizeof(struct sixxs_thread));
	if (!t)
	{
		dolog(LOG_ERR, "[%s] Couldn't allocate memory for a new thread... aborting\n", description);
		exit(-1);
	}

	// Clear the memory
	memset(t, 0, sizeof(*t));

	t->description = strdup(description);
	t->start_routine = start_routine;
	t->arg = (arg ? arg : (void *)g_conf);

	// Lock here so that we add the thread before
	// it has to chance to remove itself again ;)
	pthread_mutex_lock(&g_conf->mutex);

	// Create the thread
	if (0 != pthread_create(&t->thread, NULL, thread_autoremove, t))
	{
		dolog(LOG_ERR, "[%s] Couldn't create thread... aborting\n", description);
		exit(-1);
	}

	// Add it to the list
	if (!g_conf->threads) g_conf->threads = t;
	else
	{
		for (tt = g_conf->threads; tt->next; tt = tt->next);
		tt->next = t;
	}

	D(dolog(LOG_DEBUG, "Thread 0x%x (%s) started\n", t->thread, t->description));

	pthread_mutex_unlock(&g_conf->mutex);

	// Detach the thread
	pthread_detach(t->thread);
}
