/*****************************************************
 SixXSd - Common Functions
******************************************************
 $Author: jeroen $
 $Id: common.h,v 1.3 2006-12-20 21:19:46 jeroen Exp $
 $Date: 2006-12-20 21:19:46 $
*****************************************************/

void dologA(int level, const char *mod, const char *fmt, va_list ap);
void dolog(int level, const char *mod, const char *fmt, ...);
int huprunning(void);

/* Module Logging shortcuts */
#define mdolog(level, ...) dolog(level, module, __VA_ARGS__)
#ifdef DEBUG
#define ddolog(module, ...) dolog(LOG_DEBUG, module, __VA_ARGS__)
#define mddolog(...) ddolog(module, __VA_ARGS__)
#else
#define ddolog(level, ...) {}
#define mddolog(...) {}
#endif

/* Parsing functions */
unsigned int countfields(const char *s);
bool copyfields(const char *s, unsigned int n, unsigned int count, char *buf, unsigned int buflen);
#define copyfield(s,n,buf,buflen) copyfields(s,n,1,buf,buflen)
bool findfield(const char *s, const char *f);
bool parse_userpass(const char *uri, char *username, unsigned int username_len, char *password, unsigned int password_len);

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
#define List_IsEmpty(l) (!l || (((const struct hlist *)l)->tailprev) == (struct hnode *)(l))

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

/* Loop through all the items of a list (backwards) */
#define List_Back(l,n,n2,t)					\
for								\
(								\
	n=(t)(((struct hlist *)(l))->tailprev);			\
	(n2=(t)((struct hnode *)(n))->prev);			\
	n=(t)n2							\
)

#define List_Head(l,t) (t)(((struct hlist *)(l))->head)
#define List_Tail(l,t) (t)(((struct hlist *)(l))->tailprev)
#define List_Next(n,t) (t)(((struct hnode *)(n))->next)

#ifdef _WIN32
const char *inet_ntop(int af, const void *src, char *dst, socklen_t cnt);
#endif

/* Socketpool structures */
struct socketnode
{
	struct hnode		node;
	SOCKET			socket;				/* The socket(tm) */
	unsigned int		tag;				/* Tag for identification */
	char			buf[8192];			/* 8kb of bufferspace */
	unsigned int		filled;				/* How far the buffer has been filled */
	time_t			lastrecv;			/* Last time something was received */
	void			*data;				/* User supplied data */

	uint16_t		family;				/* Address Family (AF_*) */
	uint16_t		protocol;			/* Protocol being used (IPPROTO_*) */
	uint16_t		socktype;			/* Socket Type (SOCK_*) */
	uint16_t		__padding;
};

struct socketpool
{
	fd_set			fds;
	SOCKET			hi;
	struct hlist		sockets;
};

/* Socketpool functions */
void socketpool_init(struct socketpool *pool);
void socketpool_exit(struct socketpool *pool);
struct socketnode *socketpool_accept(struct socketpool *pool, struct socketnode *sn_a, unsigned int tag);
struct socketnode *socketpool_add(struct socketpool *pool, SOCKET sock, unsigned int tag, uint16_t family, uint16_t protocol, uint16_t socktype);
void socketpool_remove(struct socketpool *pool, struct socketnode *sn);
int sn_dataleft(struct socketnode *sn);
int sn_getdata(struct socketnode *sn);
int sn_done(struct socketnode *sn, unsigned int amount);
int sn_getline(struct socketnode *sn, char *ubuf, unsigned int ubuflen);

/* Networking functions */
void socket_cleanss(struct sockaddr_storage *addr);
void socket_setnonblock(SOCKET sock);
void socket_setblock(SOCKET sock);
int use_uri(const char *mod, const char *uri, const char *defaultservice, struct socketpool *pool, unsigned int tag);
int listen_server(const char *mod, const char *hostname, const char *service, int family, int socktype, int protocol, struct socketpool *pool, unsigned int tag);
void sock_printf(SOCKET sock, const char *fmt, ...);
int sock_getline(SOCKET sockfd, char *rbuf, unsigned int rbuflen, unsigned int *filled, char *ubuf, unsigned int ubuflen);

