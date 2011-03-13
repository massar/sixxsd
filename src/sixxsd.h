/**************************************
 SixXSd - SixXS PoP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
***************************************
 $Author: jeroen $
 $Id: sixxsd.h,v 1.28 2010-01-20 13:15:19 jeroen Exp $
 $Date: 2010-01-20 13:15:19 $
**************************************/

#ifndef SIXXSD_H
#define SIXXSD_H "42LI"

#ifndef _BSD
#include <features.h>
#endif

#ifndef _OPENBSD
#ifndef _SUNOS
#ifndef _AIX
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#endif
#endif
#endif
#endif
#define __STRICT_ANSI__

#define __FAVOR_BSD 42

/* MD5 routines require the correct types */
#define __USE_BSD 1

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>
#include <syslog.h>
#include <pwd.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/utsname.h>
#include <assert.h>

#ifdef _BSD
#include <netinet/in_systm.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <net/if_tun.h>
#include <sys/uio.h>
#endif

#if defined(_SUNOS) || defined(_AIX) || defined(_DARWIN)
/* Include this as it knows quite a bit about endianess */
#include <arpa/nameser_compat.h>
#else
#ifndef _WIN32
#ifdef _BSD
#include <sys/endian.h>
#else
#include <endian.h>
#endif
#endif
#endif

#include <net/if.h>

#ifdef _LINUX
#include <netpacket/packet.h>
#include <linux/if_tun.h>
#endif

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/ioctl.h>
#include <sys/un.h>

#include <rrd.h>

#include "ayiya.h"

#ifndef UNUSED
#define UNUSED __attribute__ ((__unused__))
#endif

/* Determine Endianness */
#if BYTE_ORDER == LITTLE_ENDIAN
	/* 1234 machines */
#elif BYTE_ORDER == BIG_ENDIAN
	/* 4321 machines */
# define WORDS_BIGENDIAN 1
#else
#error unsupported endianness!
#endif

/* Not available on eg AIX */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL		0
#endif
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP		132
#endif
#ifndef IPPROTO_IPV4
#define IPPROTO_IPV4		IPPROTO_IP
#endif

#ifndef ETH_P_IPV4
#define ETH_P_IPV4		ETH_P_IP
#endif

#ifndef SOL_IPV6
#define SOL_IPV6		IPPROTO_IPV6
#endif

#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY		26
#endif

#ifndef UWORD32
#define UWORD32 u_int32_t
#endif
#include "common/md5.h"
#include "common/sha1.h"

/* Booleans */
#define false	0
#define true	(!false)
#define bool	char

/* OS Thread & Mutex Abstraction */
#ifndef _WIN32

#define SOCKET			int

struct tlssocket
{
	SOCKET			socket;
#ifdef SIXXSD_GNUTLS
	bool			tls_active;	/* TLS active? */
	gnutls_session		session;	/* The GnuTLS sesision */
#endif
};

typedef struct tlssocket	TLSSOCKET;
#define closesocket(s)		close(s)

typedef pthread_t		os_thread;
typedef pthread_t		os_thread_id;
typedef pthread_mutex_t		os_mutexA;
#define OS_GetThisThread	pthread_self
#ifdef _LINUX
#define OS_GetThisThreadId	pthread_self
#else
#define OS_GetThisThreadId	(void *)pthread_self
#endif
#define OS_Thread_Equal(a,b)	pthread_equal(a,b)
#define OS_Mutex_InitA(m)	pthread_mutex_init(m, NULL);
#define OS_Mutex_LockA(m)	pthread_mutex_lock(m)
#define OS_Mutex_ReleaseA(m)	pthread_mutex_unlock(m)
#define OS_Mutex_DestroyA(m)	pthread_mutex_destroy(m)

#else /* !_WIN32 */

#define snprintf		_snprintf
#define vsnprintf		_vsnprintf
#define strcasecmp		_stricmp
#define strncasecmp		_strnicmp
#define gmtime_r(start,teem)	memcpy(teem, gmtime(start), sizeof(struct tm))
#define gettimeofday(tv,b)	memset(tv, 0, sizeof(*tv)); (tv)->tv_sec = time(NULL);

/* OS Thread & Mutex Abstraction */
typedef HANDLE			os_thread;
typedef DWORD			os_thread_id;
typedef HANDLE			os_mutexA;
#define OS_GetThisThread	GetCurrentThread
#define OS_GetThisThreadId	GetCurrentThreadId
#define OS_Thread_Equal(a,b)	(a == b)
typedef HANDLE			os_mutex;
#define OS_Mutex_InitA(m)	*m = CreateMutex(NULL, false, NULL)
#define OS_Mutex_LockA(m)	WaitForSingleObject(m, INFINITE);
#define OS_Mutex_ReleaseA(m)	ReleaseMutex(m)
#define OS_Mutex_DestroyA(m)	CloseHandle(m)

#endif /* !_WIN32 */

#ifdef DEBUG_LOCKS
struct os_mutex
{
	const char	*who;
	os_mutexA	mutex;
};
typedef	struct os_mutex		os_mutex;
#define OS_Mutex_Init(m)	{ printf("Mutex(%p) - Init\n", (void *)&(m)->mutex); (m)->who = NULL; OS_Mutex_InitA(&(m)->mutex); }
#define OS_Mutex_Lock(m,n)	{ printf("Mutex(%p, %s) - Get (p=%s)\n", (void *)&(m)->mutex, n, (m)->who ? (m)->who : "nobody"); OS_Mutex_LockA(&(m)->mutex); printf("Mutex(%p, %s) - Ack\n", (void *)&(m)->mutex, n); (m)->who = n; }
#define OS_Mutex_Release(m,n)	{ printf("Mutex(%p, %s) - Release\n", (void *)&(m)->mutex, n); (m)->who = NULL; OS_Mutex_ReleaseA(&(m)->mutex); }
#define OS_Mutex_Destroy(m)	{ printf("Mutex(%p) - Destroy\n", (void *)&(m)->mutex); (m)->who = NULL; OS_Mutex_DestroyA(&(m)->mutex); }
#else
#define os_mutex		os_mutexA
#define OS_Mutex_Init(m)	OS_Mutex_InitA(m)
#define OS_Mutex_Lock(m,n)	OS_Mutex_LockA(m)
#define OS_Mutex_Release(m,n)	OS_Mutex_ReleaseA(m)
#define OS_Mutex_Destroy(m)	OS_Mutex_DestroyA(m)
#endif

#include "common/common.h"

#ifdef DEBUG
#define D(x) x
#else
#define D(x) {}
#endif

#define MAXLEN 128

enum iface_type {
	IFACE_UNSPEC = 0,					/* Not in use / invalid */
	IFACE_IGNORE,						/* Ignore this interface for syncs */
	IFACE_NULL,						/* NULL interface */
	IFACE_PROTO41,						/* Protocol-41 (SIT/6in4) */
	IFACE_PROTO41_HB,					/* Normal proto-41 but with heartbeats */
	IFACE_AYIYA						/* Anything In Anything */
};

enum iface_state {
	IFSTATE_DISABLED = 0,					/* Interface is disabled */
	IFSTATE_UP,						/* Interface is up */
	IFSTATE_DOWN						/* Interface is down (either admin or user) */
};

/*
 * The maximum time in seconds that the
 * client clock is allowed to be off,
 * thus use ntp synced clocks :)
 */
#define CLOCK_OFF	120

struct sixxs_prefix
{
	os_mutex		mutex;				/* Per Prefix mutex */
	struct sixxs_prefix	*next;				/* Next prefix for this interface */

	unsigned int		interface_id;			/* Interface ID over which this prefix runs */
	unsigned int		length;				/* Length of the prefix (/48 etc) */

	struct in6_addr		prefix;				/* Prefix */
	struct in6_addr		nexthop;			/* The nexthop */

	bool			valid;				/* Is this structure valid? */
	bool			is_tunnel;			/* Prefix is a tunnel */
	bool			is_popprefix;			/* Prefix is a PoP Prefix */
	bool			enabled;			/* Enabled? */
	bool			synced;				/* Synchronized with kernel? */
	bool			ignore;				/* Ignore this route? (also used for BGP) */
	char			__padding[2];
};

struct sixxs_interface
{
	os_mutex		mutex;				/* Per interface mutex */
	struct sixxs_prefix	*prefixes;			/* Prefixes associated with this interface */

	unsigned int		interface_id;			/* Interface ID */

	unsigned int		kernel_ifindex;			/* Kernel's interface index */
	unsigned int		kernel_flags;			/* Kernel's flags */

	char			name[MAXLEN];			/* Interface Name */
	enum iface_type		type;				/* Type of this interface (IFACE_*) */
	enum iface_state	state;				/* State of this interface (IFSTATE_*) */
	bool			synced_link;			/* Link up/down? (configured or not) */
	bool			synced_addr;			/* Address up/down? (configured or not) */
	bool			synced_local;			/* Local addr route configured or not */
	bool			synced_remote;			/* Remote addr route configured or not */
	bool			synced_subnet;			/* Subnet configured or not */

	bool			running;			/* Tunnel process running? */

	unsigned int		subnets_got;			/* Number of subnets it has */
	unsigned int		subnets_up;			/* Number of subnets that are up */

	struct in_addr		ipv4_us,			/* IPv4 tunnel PoP side */
				ipv4_them;			/* IPv4 tunnel User side */

	struct in6_addr		ipv6_us,			/* Primary IPv6 endpoints */
				ipv6_them,
				ipv6_ll;			/* Some tunneltypes don't have LL's */
								/* Thus we generate them from the ipv6_us */
	unsigned int		prefixlen;			/* Length of the prefix on the interface */

	unsigned int		mtu;				/* Maximum Transmission Unit */
	unsigned int		ttl;				/* TTL */

	/* Statistics ICMPv6-wise on the remote endpoint */
	time_t			prevdead;			/* Previous time we thought it was dead */
	time_t			lastalive;			/* When it was lastalive */
	float			latency;			/* Latency */
	float			loss;				/* Packetloss */

	/* Heartbeat & AYIYA specific (IFACE_PROTO41_HB + IFACE_AYIYA) */
	time_t			hb_lastbeat;			/* Last heartbeat we got */
	char			password[128];			/* password */

	/* AYIYA specific (IFACE_AYIYA) */
	unsigned int		ayiya_sport;			/* Server port */
	unsigned int		ayiya_port;			/* Port on the side of the client */
	unsigned int		ayiya_protocol;			/* Protocol that is in use (PROTO_(UDP|TCP|...) */
	int			ayiya_fd;			/* File descriptor for the tun/tap device */
	unsigned char		ayiya_hash[SHA1_DIGEST_LENGTH];	/* SHA1 Hash of the shared secret. */

	/* Statistics */
	uint64_t		inoct,				/* Input Octets */
				outoct,				/* Output Octets */
				inpkt,				/* Input Packets */
				outpkt;				/* Output Packets */
};

struct sixxs_pop_prefix
{
	struct sixxs_pop_prefix	*next;				/* Next in the chain */
	struct in6_addr		prefix;				/* Prefix */
	unsigned int		length;				/* Length of the prefix (/48 etc) */
};

struct sixxs_pop_ignores
{
	struct sixxs_pop_ignores *next;				/* Next in the chain */
	char			*name;				/* Devicename to ignore */
};

struct sixxs_thread
{
	struct sixxs_thread	*next;				/* Next in the chain */
	char			*description;			/* Description of this thread */
	os_thread		thread;				/* The thread */
	os_thread_id		thread_id;			/* Thread Id */

	/* The routine we are going to call with it's argument */
	void			*(*start_routine)(void *);
	void			*arg;
};

/* Our configuration structure */
struct conf
{
	/* Generic */
	bool			daemonize;			/* To Daemonize or to not to Daemonize */
	bool			running;			/* If we are running or not */
	bool			do_sync;			/* To synchronize or to not to synchronize */
	bool			do_rrd;				/* Create RRDs? */
	unsigned int		verbose;			/* Verbosity level */
	FILE			*logfile;			/* logfile */
	time_t			starttime;			/* Time that we started running */

	/* Mutex */
	os_mutex		mutex_thread;			/* Mutex for Threads */
	os_mutex		mutex_interfaces;		/* Mutex for Interfaces */
	os_mutex		mutex_prefixes;			/* Mutex for Prefixes */
	os_mutex		mutex_pop_prefixes;		/* Mutex for POP Prefixes */
	os_mutex		mutex_log;			/* Mutex for Logging */

	/* PoP Configuration */
	char			*pop_name;			/* Name of this PoP */
	struct in_addr		pop_ipv4;			/* IPv4 address of this PoP */
	struct in6_addr		pop_ipv6;			/* IPv6 address of this PoP */
	struct sixxs_pop_prefix	*pop_prefixes;			/* Prefixes handled by this PoP */
	
	char			*pop_tunneldevice;		/* Interface name prefix */
	char			*pop_ignoredevices;		/* Interface names to ignore */
	unsigned int		pop_hb_sendinterval;		/* Heartbeat Send Interval */
	unsigned int		pop_hb_timeout;			/* Heartbeat Timeout */

	char			*homedir;			/* Homedir */

	/* Could hash or tree these two for more performance */
	struct sixxs_interface	*interfaces;			/* All the interfaces in this system */
	struct sixxs_prefix	*prefixes;			/* All the prefixes in this system */

	unsigned int		max_interfaces;			/* Maximum number of prefixes */
	unsigned int		max_prefixes;			/* Maximum number of routes */

	unsigned int		loopback_ifindex;		/* Ifindex of the loopback device */

	/* Statistics */
	struct
	{
		time_t		starttime;			/* When did we start */
	}			stats;

	/* Threads */
	struct sixxs_thread	*threads;			/* The threads in this system. */
};

/*********************************************************
  Functions and variables accessible from multiple files
*********************************************************/
/* sixxsd.c */
extern struct conf *g_conf;
void sync_complete(void);

/* os_*.c */
bool os_init(void);
bool os_sync_complete(void);

/* Actually only for use by interface.c */
bool os_sync_routes(struct sixxs_interface *iface);
bool os_int_set_endpoint(struct sixxs_interface *iface, struct in_addr ipv4_them);
bool os_int_set_state(struct sixxs_interface *iface, enum iface_state state);
bool os_int_set_mtu(struct sixxs_interface *iface, unsigned int mtu);
bool os_int_set_ttl(struct sixxs_interface *iface, unsigned int ttl);
bool os_int_rename(struct sixxs_interface *iface, bool back);

/* interface.c */
bool int_set_state(struct sixxs_interface *iface, enum iface_state state);
bool int_sync(struct sixxs_interface *iface);
bool int_set_endpoint(struct sixxs_interface *iface, struct in_addr ipv4_them);
bool int_set_port(struct sixxs_interface *iface, unsigned int port);
bool int_beat(struct sixxs_interface *iface);
struct sixxs_interface *int_get(unsigned int id);
struct sixxs_interface *int_get_by_index(unsigned int id);
struct sixxs_interface *int_get_by_name(const char *name);
bool int_reconfig(unsigned int id, struct in6_addr *ipv6_us, struct in6_addr *ipv6_them, int prefixlen, struct in_addr ipv4_us, struct in_addr ipv4_them, enum iface_type type, enum iface_state state, unsigned int mtu, char *password);

/* prefix.c */
struct sixxs_prefix *pfx_get(struct in6_addr *ipv6_them, unsigned int prefixlen);
void pfx_reconfig(struct in6_addr *prefix, unsigned int length, struct in6_addr *nexthop, bool enabled, bool ignore, bool is_tunnel, bool is_popprefix, struct sixxs_interface *iface);
bool pfx_issubnet(struct in6_addr *a_pfx, unsigned int a_len, struct in6_addr *b_pfx, unsigned int b_len);

/* thread.c */
void thread_add(const char *description, void *(*__start_routine) (void *), void *arg, bool detach);
void thread_cleanup(void);

/* cfg.c */
void cfg_init(void);
bool cfg_fromfile(const char *filename);
bool cfg_pop_prefix_check(struct in6_addr *prefix, unsigned int length);

/* hb.c */
void hb_init(void);

/* ayiya.c */
void ayiya_init(void);
bool ayiya_start(struct sixxs_interface *iface);
bool ayiya_stop(struct sixxs_interface *iface);

/* traffic.c */
void traffic_init(void);

/* latency.c */
void latency_init(void);

#endif
