/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2013 All Rights Reserved
***********************************************************/

#ifndef LIST_H
#define LIST_H LI42

/* Node/List Functions */
struct hnode
{
	struct hnode	*next,		/* Next in the list */
			*prev;		/* Previous in the list */
};

struct hlist
{
	struct hnode	*head,		/* The beginning of the list */
			*tail,		/* The tail of the list */
			*tailprev;	/* The previous of the tail of the list */
};

/* Is the list empty? */
#define List_IsEmpty(l) ((!(l)) || (((struct hlist *)((struct hlist *)(l))->tailprev)) == (l))

/* Create a new list */
#define List_New(_l)						\
do								\
{								\
	struct hlist	*l = (struct hlist *)(_l);		\
	l->tailprev	= (struct hnode *)l;			\
	l->tail		= NULL;					\
	l->head		= (struct hnode *)&l->tail;		\
} while (0)

#define List_AddHead(_l,_n)					\
do								\
{								\
	struct hlist		*l = (struct hlist *)(_l);	\
	List_Insert(l->head, _n);				\
} while (0)

/* Add a item at the end of a list */
#define List_AddTail(_l,_n)					\
do								\
{								\
	List_Append(((struct hlist *)(_l))->tailprev, _n);	\
} while (0)

/* Remove a node from any list */
#define List_Remove(_n)						\
do								\
{								\
	struct hnode *__n = (struct hnode *)(_n);		\
	if (!__n->prev) break;					\
	if (!__n->next) break;					\
	__n->prev->next = __n->next;				\
	__n->next->prev = __n->prev;				\
	__n->next	= NULL;					\
	__n->prev	= NULL;					\
} while (0)

/* Insert node i in the list where n is part of */
#define List_Insert(_n,_i)					\
do								\
{								\
	struct hnode *__n = (struct hnode *)(_n);		\
	struct hnode *__i = (struct hnode *)(_i);		\
	__n->prev->next = __i;					\
	__i->next = __n;					\
	__i->prev = __n->prev;					\
	__n->prev = __i;					\
} while (0)

/* Append node i to the list where n is part of */
#define List_Append(_n,_i)					\
do								\
{								\
	struct hnode *__n = (struct hnode *)(_n);		\
	struct hnode *__i = (struct hnode *)(_i);		\
	__i->next = __n->next;					\
	__n->next->prev = __i;					\
	__i->prev = __n;					\
	__n->next = __i;					\
} while (0)

/* Swap the order of two items */
#define List_Swap(_n,_m)					\
do								\
{								\
	struct hnode *n = (struct hnode *)(_n);			\
	struct hnode *m = (struct hnode *)(_m);			\
	n->prev->next = m;					\
	m->next->prev = n;					\
	m->prev = n->prev;					\
	n->next = m->next;					\
	n->prev = m;						\
	m->next = n;						\
}

/* Loop through all the items of a list */
#define List_For(l,n,n2,t)					\
for								\
(								\
	n=(t)(((struct hlist *)(l))->head);			\
	l && (n2=(t)((struct hnode *)(n))->next);		\
	n=(t)n2							\
)

#define ListItem_For(i,n,n2,t)					\
for								\
(								\
	n=(t)(((struct hnode *)(i))->next);			\
	i && (n2=(t)((struct hnode *)(n))->next);		\
	n=(t)n2							\
)

/* Loop through all the items of a list (backwards) */
#define List_Back(l,n,n2,t)					\
for								\
(								\
	n=(t)(((struct hlist *)(l))->tailprev);			\
	(n2=(t)((struct hnode *)(n))->prev);			\
	n=(t)n2							\
)

#define ListItem_Back(i,n,n2,t)					\
for								\
(								\
	n=(t)(((struct hnode *)(i))->prev);			\
	(n2=(t)((struct hnode *)(n))->prev);			\
	n=(t)n2							\
)

#define List_Head(l,t) (t)(((struct hlist *)(l))->head)
#define List_Tail(l,t) (t)(((struct hlist *)(l))->tailprev)
#define List_Next(n,t) (t)(((struct hnode *)(n))->next)
#define List_IsLast(n) (((struct hnode *)(n))->next)

#endif

