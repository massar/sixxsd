/**************************************
 SixXSd - SixXS POP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
***************************************
 $Author: jeroen $
 $Id: sixxsd.h,v 1.3 2005-01-31 17:05:10 jeroen Exp $
 $Date: 2005-01-31 17:05:10 $
**************************************/

#ifndef SIXXSD_H
#define SIXXSD_H "42LI"

#include <features.h>

#define _XOPEN_SOURCE 600
#define __FAVOR_BSD 42

// MD5 routines require the correct types
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

#include <net/if.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>

// Determine Endianness
#if BYTE_ORDER == LITTLE_ENDIAN
	/* 1234 machines */
#elif BYTE_ORDER == BIG_ENDIAN
	/* 4321 machines */
# define WORDS_BIGENDIAN 1
#else
#error unsupported endianness!
#endif

#ifndef UWORD32
#define UWORD32 u_int32_t
#endif
#include "common/md5.h"
#include "common/sha1.h"

// Booleans
#define false	0
#define true	(!false)
#define bool	int

#include "common/common.h"

// Some changable settings
#define PIDFILE "/var/run/sixxsd.pid"

#ifndef DEBUG
#define SIXXSD_DUMPFILE "/var/run/sixxsd.dump"
#else
#define SIXXSD_DUMPFILE "/tmp/sixxsd.dump"
#endif

// Change this to allow multiple global IPv6 addresses
#define SIXXSD_NUM_ADDRESSES 1

#ifdef DEBUG
#define D(x) x
#else
#define D(x) {}
#endif

#define MAXLEN 128

enum iface_type {
	IFACE_UNSPEC = 0,					// Not in use / invalid
	IFACE_IGNORE,						// Ignore this interface for syncs
	IFACE_PROTO41,						// Protocol-41 (SIT/6in4)
	IFACE_PROTO41_HB,					// Normal proto-41 but with heartbeats
	IFACE_TINC,						// tinc tunnel
	IFACE_AYIYA,						// Anything In Anything
};

enum iface_state {
	IFSTATE_DISABLED = 0,					// Interface is disabled
	IFSTATE_UP,						// Interface is up
	IFSTATE_DOWN,						// Interface is down (either admin or user)
};

#define CLOCK_OFF	120	// The maximum time in seconds that the
				// client clock is allowed to be off, thus use ntp synced clocks :)

struct sixxs_interface
{
	unsigned int		interface_id;			// Interface ID

	enum iface_type		type;				// Type of this interface (IFACE_*)
	enum iface_state	state;				// State of this interface (IFSTATE_*)

	char			name[MAXLEN];			// Interface Name

	struct in_addr		ipv4_us,			// IPv4 tunnel endpoints
				ipv4_them;

	struct in6_addr		ipv6_us,			// Primary IPv6 endpoints
				ipv6_them;

	bool			sync_seen;			// Was it seen in the last full sync?

	// Heartbeat specific
	// (IFACE_PROTO41_HB + IFACE_AYIYA)
	time_t			hb_lastbeat;			// Last heartbeat we got
	char			hb_password[52];		// Heartbeat password

	// AYIYA specific
	// (IFACE_AYIYA)
	unsigned int		ayiya_port;			// Port on the side of the client
	unsigned int		ayiya_protocol;			// Protocol that is in use (PROTO_(UDP|TCP|...)
	int			ayiya_fd;			// File descriptor for the tun/tap device
	unsigned char		ayiya_hash[SHA1_DIGEST_LENGTH];	// SHA1 Hash of the shared secret.

	// Statistics
	uint64_t		inoct,				// Input Octets
				outoct,				// Output Octets
				inpkt,				// Input Packets
				outpkt;				// Output Packets
};

struct sixxs_prefix
{
	bool			valid;				// Is this structure valid?
	
	bool			is_tunnel;			// Prefix is a tunnel
	unsigned int		interface_id;			// Interface ID over which this prefix runs

	struct in6_addr		prefix;				// Prefix
	unsigned int		length;				// Length of the prefix (/48 etc)
	struct in6_addr		nexthop;			// The nexthop

	bool			enabled;			// Enabled?
	bool			sync_seen;			// Was it seen in the last full sync?
	bool			ignore;				// Ignore this route?
};

struct sixxs_pop_prefix
{
	struct sixxs_pop_prefix	*next;				// Next in the chain
	struct in6_addr		prefix;				// Prefix
	unsigned int		length;				// Lenght of the prefix (/48 etc)
};

struct sixxs_pop_ignores
{
	struct sixxs_pop_ignores *next;				// Next in the chain
	char			*name;				// Devicename to ignore
};

struct sixxs_thread
{
	struct sixxs_thread	*next;				// Next in the chain
	char			*description;			// Description of this thread
	pthread_t		thread;				// The thread

	// The routine we are going to call with it's argument
	void			*(*start_routine)(void *);
	void			*arg;
};

// Our configuration structure
struct conf
{
	// Generic
	bool			daemonize;			// To Daemonize or to not to Daemonize
	bool			running;			// If we are running or not

	// Mutex
	pthread_mutex_t		mutex;				// Mutex for * but:

	// POP Configuration
	char			*pop_name;			// Name of this POP
	struct in_addr		pop_ipv4;			// IPv4 address of this POP
	struct in6_addr		pop_ipv6;			// IPv6 address of this POP
	struct sixxs_pop_prefix	*pop_prefixes;			// Prefixes handled by this POP
	
	char			*pop_tunneldevice;		// Interface name prefix
	char			*pop_ignoredevices;		// Interface names to ignore
	bool			pop_hb_supported;		// Is heartbeat are supported?
	unsigned int		pop_hb_sendinterval;		// Heartbeat Send Interval
	unsigned int		pop_hb_timeout;			// Heartbeat Timeout
	bool			pop_tinc_supported;		// Is tinc are supported?
	char			*pop_tinc_device;		// tinc device
	char			*pop_tinc_config;		// tinc configuration

	struct sixxs_interface	*interfaces;			// All the interfaces in this system
	struct sixxs_prefix	*prefixes;			// All the prefixes in this system

	unsigned int		max_interfaces;			// Maximum number of prefixes
	unsigned int		max_prefixes;			// Maximum number of routes

	// Statistics
	FILE			*stat_file;			// The file handle of ourdump file
	char			*stat_filename;			// Name of the file to dump into
	struct
	{
		time_t		starttime;			// When did we start
	}			stats;

	// Threads
	struct sixxs_thread	*threads;			// The threads in this system.
};

// Global Stuff
extern struct conf *g_conf;

/*********************************************************
  Functions and variables accessible from multiple files
*********************************************************/
///////////////////////////////////////////////////////////
// sixxsd.c
extern struct conf *g_conf;

/// Synchronisation
bool sync_complete();

///////////////////////////////////////////////////////////
// os_*.c
extern bool os_init();
extern bool os_sync_interface(struct sixxs_interface *iface);

///////////////////////////////////////////////////////////
// interface.c
bool int_sync(struct sixxs_interface *iface);
bool int_set_endpoint(struct sixxs_interface *iface, struct in_addr ipv4_them);
bool int_set_port(struct sixxs_interface *iface, unsigned int port);
bool int_beat(struct sixxs_interface *iface);
struct sixxs_interface *int_get(unsigned int id);
bool int_reconfig(unsigned int id, struct in6_addr *ipv6_us, struct in6_addr *ipv6_them, int prefixlen, struct in_addr ipv4_them, enum iface_type type, enum iface_state state, char *password);

///////////////////////////////////////////////////////////
// prefix.c
struct sixxs_prefix *pfx_get(struct in6_addr *ipv6_them, unsigned int prefixlen);
void pfx_reconfig(struct in6_addr *prefix, unsigned int length, struct in6_addr *nexthop, bool enabled, bool is_tunnel, unsigned int tunnel_id);

///////////////////////////////////////////////////////////
// thread.c
void thread_add(char *description, void *(*__start_routine) (void *), void *arg);

///////////////////////////////////////////////////////////
// cfg.c
extern void *cfg_thread(void *arg);
extern bool cfg_fromfile(char *filename);

///////////////////////////////////////////////////////////
// hb.c
extern void *hb_thread(void *arg);

///////////////////////////////////////////////////////////
// ayiya.c
extern void *ayiya_thread(void *arg);
bool ayiya_init(struct sixxs_interface *iface);

///////////////////////////////////////////////////////////
// traffic.c
extern void *traffic_thread(void *arg);

#endif
