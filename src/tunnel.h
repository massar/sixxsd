/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2013 All Rights Reserved
***********************************************************/

#ifndef TUNNEL_H
#define TUNNEL_H "SixXSd Tunnel definitions"

#include "sixxsd.h"

#define SIXXSD_TUNNEL_NONE		0xffff				/* No tunnel (sixxsd address) */
#define SIXXSD_TUNNEL_UPLINK		0xfffe				/* Uplink of the tunnel */

#define SIXXSD_TUNNEL_IP_US		0x0001				/* Our side of the tunnel */
#define SIXXSD_TUNNEL_IP_THEM		0x0002				/* Their side of the tunnel */

enum sixxsd_tunnel_type
{
	SIXXSD_TTYPE_NONE	= 0,					/* Not a tunnel (aka tunnel is not used) */
	SIXXSD_TTYPE_IGNORE,						/* Ignore this interface (eg TINC) */
	SIXXSD_TTYPE_PROTO41,						/* Proto-41 static */
	SIXXSD_TTYPE_PROTO41_HB,					/* Proto-41 Heartbeat */
	SIXXSD_TTYPE_AYIYA,						/* AYIYA */
	SIXXSD_TTYPE_MAX
};

/* XXX: Sent ICMP_ADMIN_UNREACHABLE when tunnel is admin disabled, sent normal unreachable when it is DOWN :) */
enum sixxsd_tunnel_state
{
	SIXXSD_TSTATE_NONE	= 0,					/* Not a tunnel (aka tunnel is not used) */
	SIXXSD_TSTATE_DISABLED,						/* Tunnel is disabled (PoP doesn't know about user/admin state) */
	SIXXSD_TSTATE_DOWN,						/* Tunnel is down (no heartbeat) */
	SIXXSD_TSTATE_UP						/* Tunnel is up */
};

/* Keep synced with tunnel_error_name() in tunnel.c */
enum sixxsd_tunnel_errors
{
	SIXXSD_TERR_TUN_ENCAPS_PACKET_TOO_BIG = 0,			/* Packet Too Big when sending an encapsulated packet */
	SIXXSD_TERR_TUN_DISABLED,					/* Packet received for a disabled tunnel */
	SIXXSD_TERR_TUN_CLOCK_OFF,					/* Packet sent was not inside clock limits */
	SIXXSD_TERR_TUN_ENCAPS_OUT_ERR,					/* Output error when sending an encapsulated packet */
	SIXXSD_TERR_TUN_SAME_IO,					/* Same input as output interface */
	SIXXSD_TERR_TUN_WRONG_SOURCE_IPV6,				/* IPv6 packet with a wrong source address */
	SIXXSD_TERR_TUN_WRONG_SOURCE_IPV4,				/* IPv4 packet with a wrong source address */
	SIXXSD_TERR_TUN_FROM_UPLINK,					/* Tunnel sourced packet came in from uplink */
	SIXXSD_TERR_TUN_PAYLOAD_NOT_IPV6,				/* Payload was supposed to be IPv6 but is not */
	SIXXSD_TERR_TUN_PAYLOAD_NOT_IPV4,				/* Payload was supposed to be IPv4 but is not */
	SIXXSD_TERR_AYIYA_HASHFAIL,					/* Tunnel Hash verification failed (AYIYA) */
	SIXXSD_TERR_AYIYA_FOR_NON_AYIYA,				/* Received an AYIYA packet for a non-AYIYA tunnel */
	SIXXSD_TERR_AYIYA_INVALIDFORWARD,				/* Can't forward a packet with an invalid protocol */
	SIXXSD_TERR_HB_HASHFAIL,					/* Tunnel Hash verification failed (heartbeat) */
	SIXXSD_TERR_HB_FOR_NON_HB,					/* Heartbeat received for non-heartbeat tunnel */
	SIXXSD_TERR_HB_NO_IPV4,						/* No IPv4/sender found in HB packet */
	SIXXSD_TERR_HB_SENDER_MISMATCH,					/* Sender mismatch */
	SIXXSD_TERR_HB_NOTIME,						/* No time found in packet */
	SIXXSD_TERR_ICMPV4_ERROR,					/* We received an ICMPv4 error */
	SIXXSD_TERR_ICMPV4_ECHO_REQUEST,				/* We received an ICMPv4 Echo Request */
	SIXXSD_TERR_MAX
};

struct sixxsd_tunerr
{
	uint64_t			count;				/* How many we have seen */
	uint64_t			last_seen;			/* Last time we saw it */
	IPADDRESS			last_ip;			/* Last IP address which caused it */
	uint8_t				packet[128];			/* First 128 bytes of the packet that caused the error */
	uint64_t			orgplen;			/* How long the original packet was */
};

struct sixxsd_tunnel
{
	IPADDRESS			ip_them;			/* IP address of the remote end of the tunnel */
	struct sixxsd_context		*debug_ctx;			/* Context to send debug output to */
	uint32_t			tunnel_id;			/* The T<xxx> in the database */

	uint16_t			mtu;				/* MTU of this tunnel */

	enum sixxsd_tunnel_type		type;				/* Type of this tunnel */
	enum sixxsd_tunnel_state	state;				/* State of this tunnel */

	/* AYIYA */
	uint16_t			ayiya_port_us, ayiya_port_them;	/* Our and their port number */
	uint8_t				ayiya_af;			/* Which Address Family? */
	uint8_t				ayiya_socktype;			/* Which Socket Type is used (STREAM/DGRAM/SEQPACKET) */
	uint8_t				ayiya_protocol;			/* Which IP Protocol is used (TCP/UDP/SCTP) */
	uint8_t				ayiya_hash_type;		/* AYIYA hash mode */
	uint8_t				ayiya_sha1[SHA1_DIGEST_LENGTH];	/* SHA1 hash */

	/* Heartbeat */
	uint8_t				hb_password[132];		/* Heartbeat password */

	/* Heartbeat & AYIYA */
	uint64_t			lastbeat;			/* Timestamp of last beat */

	/* Traffic & Latency statistics */
	struct sixxsd_stats		stats;				/* Statistics */

	/* Errors */
	struct sixxsd_tunerr		errors[SIXXSD_TERR_MAX];	/* The errors we saw */
};

struct sixxsd_tunnels
{
	IPADDRESS			prefix;				/* Prefix (always a /64) */
	char				prefix_asc[NI_MAXHOST];		/* Cached textual representation of prefix */
	uint8_t				__padding[7];

	uint64_t			tunnel_hi;			/* Highest tunnel_id in-use */
	struct sixxsd_tunnel		tunnel[SIXXSD_TUNNELS_MAX];	/* The tunnels  */

	BOOL				online;				/* Did we tell the kernel about it? */
};

int tunnel_init(struct sixxsd_context *ctx);
uint16_t tunnel_get(IPADDRESS *addr, BOOL *istunnel);
uint16_t tunnel_find(IPADDRESS *addr);
struct sixxsd_tunnel *tunnel_grab(const uint16_t tid);
BOOL tunnel_state_check(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, BOOL is_response);
VOID tunnel_account_packet_in(const uint16_t in_tid, unsigned int packet_len);
VOID tunnel_account_packet_out(const uint16_t out_tid, unsigned int packet_len);
const char *tunnel_state_name(enum sixxsd_tunnel_state state);
const char *tunnel_type_name(enum sixxsd_tunnel_type type);
VOID tunnel_log(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, enum sixxsd_tunnel_errors err, const IPADDRESS *src);
VOID tunnel_log4(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, enum sixxsd_tunnel_errors err, const struct in_addr *src);
VOID tunnel_debug(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, const char *fmt, ...) ATTR_FORMAT(printf, 5, 6);

#endif /* TUNNEL_H */

