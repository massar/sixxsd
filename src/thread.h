/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2013 All Rights Reserved
************************************************************
 Thread Management
***********************************************************/

#ifndef THREAD_H
#define THREAD_H "Thread Management"

#include "sixxsd.h"

enum thread_states
{
	thread_state_dying		= 0,
	thread_state_running		= 1,
	thread_state_sleeping		= 2,
	thread_state_selectwait		= 3,
	thread_state_ioread		= 4
};

struct sixxsd_thread
{
	struct sixxsd_thread	*next;				/* Next in the chain */
	char			*description;			/* Description of this thread */
	char			*notice;			/* Notice */
	os_thread		thread;				/* The thread */
	os_thread_id		thread_id;			/* Thread Identifier */
	uint64_t		state;				/* Sleeping? */
	uint64_t		starttime;			/* Time we started running this thread */
	mutex			mutex;				/* Lock protecting this thread */
	pthread_cond_t		cond;				/* Condition variable for this thread */
	BOOL			cancelable;			/* Directly cancel this thread at exit time? */

        /* The routine we are going to call with its argument */
	PTR			*(*start_routine)(PTR *);
	PTR			*arg;
};

os_thread_id thread_add(struct sixxsd_context *ctx, const char *description, PTR *(*start_routine)(PTR *), PTR *arg, struct sixxsd_thread **store, BOOL cancelable);
VOID thread_remove(struct sixxsd_thread *thread, BOOL dolock);
BOOL thread_setnotice(const char *notice);
BOOL thread_setstate(enum thread_states state);
BOOL thread_sleep(unsigned int seconds, unsigned int nsecondss);
VOID thread_exit(VOID);
struct sixxsd_thread *thread_getthis(VOID);
int thread_list(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[]);

#endif /* THREAD_H */

