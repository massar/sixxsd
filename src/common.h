/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2012 All Rights Reserved
***********************************************************/

#ifndef COMMON_H
#define COMMON_H LI42

#include "platform.h"

/* Alignment-safe copies */
#define mcp8(dst,off)		{ dst = buffer[off]; }
#define mcpSX(dst,off,len)	{ memcpy(&(dst), &buffer[off], len); }
#define mcp16S(dst,off)		{ mcpSX(t16, off, 2);	dst = t16; }
#define mcp32S(dst,off)		{ mcpSX(t32, off, 4);	dst = t32; }
#define mcp64S(dst,off)		{ mcpSX(t64, off, 8);	dst = t64; }
#define mcp16(dst,off)		{ mcp16S(t16, off);	dst = ntohs(t16); }
#define mcp32(dst,off)		{ mcp32S(t32, off);	dst = ntohl(t32); }
#define mcp64(dst,off)		{ mcp64S(t64, off);	dst = ntohll(t64); }

/* Store 24bit numbers in 32bit fields */
#if BYTE_ORDER == LITTLE_ENDIAN
#define mcp24(dst,off)		{ t32 = 0; memcpy(&(t32), &buffer[off], 3); dst = ntohl(t32); }
#else
#define mcp24(dst,off)		{ t32 = 0; memcpy(&(t32)+1, &buffer[off], 3); dst = t32; }
#endif

#define mcp(dst,off,len)			\
{						\
	if (len == 2)				\
	{					\
		mcp16(dst, off);		\
	}					\
	else if (len == 3)			\
	{					\
		mcp24(dst, off);		\
	}					\
	else if (len == 4)			\
	{					\
		mcp32(dst, off);		\
	}					\
	else					\
	{					\
		mcp64(dst ,off);		\
	}					\
}

#define mcalloc(size, name) calloc(1, size)
#define mfree(ptr, name, size) free(ptr)
#define mstrdup(s) strdup(s)
PTR *mrealloc(PTR *ptr, size_t newsize, size_t oldsize);

VOID doelog(int level, int errnum, const char *module, const char *ATTR_RESTRICT fmt, ...) ATTR_FORMAT(printf, 4, 5);
VOID dolog(int level, const char *module, const char *ATTR_RESTRICT fmt, ...) ATTR_FORMAT(printf, 3, 4);

/* Parsing functions */
size_t countfields(const char *s);
BOOL copyfields(const char *s, size_t n, size_t count, char *buf, size_t buflen);
#define copyfield(s,n,buf,buflen) copyfields(s,n,1,buf,buflen)
BOOL findfield(const char *s, const char *f);
BOOL parse_userpass(const char *uri, char *username, size_t username_len, char *password, size_t password_len);

#ifndef __sync_fetch_and_add
#define __sync_fetch_and_add(v, n) {*v += n; }
#endif

BOOL isyes(const char *buf);
#define yesno(x) (x ? "yes" : "no")
#define sex(x) (x ? "female" : "male")

#define snprintfok(ret, bufsize) (((ret) >= 0) && (((unsigned int)(ret)) < bufsize))

BOOL ipaddress_is_ipv4(const IPADDRESS *address);
VOID ipaddress_set_ipv4(IPADDRESS *a, const struct in_addr *ipv4);
VOID ipaddress_set_ipv6(IPADDRESS *a, const struct in6_addr *ipv6);
VOID ipaddress_make_ipv4(IPADDRESS *a, const struct in_addr *ipv4);
#define ipaddress_make_ipv6(a,i) ipaddress_set_ipv6(a,i)
BOOL ipaddress_is_unspecified(const IPADDRESS *address);

/* Misc */
const char *inet_ntopA(const IPADDRESS *src, char *dst, socklen_t cnt);
const char *inet_ntopAL(const IPADDRESS *src, unsigned int len, char *dst, socklen_t cnt);
int inet_ptonA(const char *src, IPADDRESS *dst, unsigned int *length);
int get_utc_offset(VOID);
uint64_t gettime(VOID);
uint64_t gettime_us(VOID);
#define time_us_sec(t) (t / 1000000)
#define time_us_us(t) (t % 1000000)
#define time_us_msec(t) (((float)time_us_sec(t) * 1000) + ((float)time_us_us(t) / 1000))

#define MKDIR(directory, perms) mkdir(directory, perms)

/* Socketpool structures */
struct socketnode
{
	struct hnode		node;
	uint64_t		tag;				/* Tag for identification */
	uint64_t		filled;				/* How far the buffer has been filled */
	time_t			lastrecv;			/* Last time something was received */
	PTR			*data;				/* User supplied data */

	uint16_t		family;				/* Address Family (AF_*) */
	uint16_t		protocol;			/* Protocol being used (IPPROTO_*) */
	uint16_t		socktype;			/* Socket Type (SOCK_*) */
	uint16_t		__padding;
	SOCKET			socket;				/* The socket(tm) */

	char			buf[8192];			/* 8kb of bufferspace */
};

struct socketpool
{
	fd_set			fds;
	struct hlist		sockets;
	SOCKET			hi;
};

/* Socketpool functions */
VOID socketpool_init(struct socketpool *pool);
VOID socketpool_exit(struct socketpool *pool);
struct socketnode *socketpool_accept(struct socketpool *pool, struct socketnode *sn_a, uint32_t tag);
struct socketnode *socketpool_add(struct socketpool *pool, SOCKET sock, uint32_t tag, uint16_t family, uint16_t protocol, uint16_t socktype);
VOID socketpool_remove(struct socketpool *pool, struct socketnode *sn);
uint64_t sn_dataleft(struct socketnode *sn);
int sn_getdata(struct socketnode *sn);
uint64_t sn_done(struct socketnode *sn, uint64_t amount);
int sn_getline(struct socketnode *sn, char *ubuf, uint64_t ubuflen);

/* Networking functions */
VOID sock_cleanss(struct sockaddr_storage *addr);
VOID sock_setnonblock(SOCKET sock);
VOID sock_setblock(SOCKET sock);
SOCKET sock_connect(char *buf, unsigned int buflen, const char *hostname, const char *service, int family, int socktype, int protocol, const char *bind_hostname, const char *bind_service);
SOCKET use_uri(char *buf, unsigned int buflen, BOOL doconnect, const char *uri, const char *defaultservice, struct socketpool *pool, uint32_t tag);
int sock_printf(SOCKET sock, const char *ATTR_RESTRICT fmt, ...) ATTR_FORMAT(printf, 2, 3);
int sock_getline(SOCKET sockfd, char *rbuf, uint64_t rbuflen, uint64_t *filled, char *ubuf, uint64_t ubuflen);

#if defined(DEBUG) || defined(DEBUG_LOCKS) || defined(DEBUG_STACK)
VOID *get_caller(unsigned int skip);
VOID dump_stacktrace(VOID **trace, uint64_t *trace_size, unsigned int skip);
VOID format_stacktrace(char *buf, unsigned int length, VOID **trace, unsigned int trace_size);
VOID output_stacktrace(VOID);
#endif

#endif

