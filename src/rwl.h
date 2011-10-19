/************************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2011 All Rights Reserved
*************************************************************
 $Author: $
 $Id: $
 $Date: $

 Read/Write Lock definitions
************************************************************/

#ifndef RWL_H
#define RWL_H

#include "sixxsd.h"

#ifdef DEBUG_LOCKS
struct rwl_node
{
	os_thread_id	thread_id;		/* Who has the lock */
	VOID		*trace[16];		/* Backtrace of last locker */
	uint64_t	trace_size;		/* Size of the backtrace */
	uint64_t	readers;		/* Is the thread reading (allow multiple readers from same thread) */
	uint64_t	writers;		/* Or is it writing? (Only allow this once though) */
};
#endif

struct rwl
{
	mutex		mutex;			/* Lock for changing readers/writers */
	mutex		mutexW;			/* Lock held when something is writing */
	unsigned int	readers;		/* How many readers are in */
	unsigned int	writers;		/* How many writers are waiting */
#ifdef DEBUG_LOCKS
	struct rwl_node	locks[64];		/* Allow for 64 outstanding locks (thus 64 threads) */
#endif
};

typedef struct rwl rwl;

VOID rwl_init(rwl *rwl);
VOID rwl_destroy(rwl *rwl);
VOID rwl_lockR(rwl *rwl);
VOID rwl_releaseR(rwl *rwl);
VOID rwl_lockW(rwl *rwl);
VOID rwl_releaseW(rwl *rwl);

#endif /* RWL_H */

