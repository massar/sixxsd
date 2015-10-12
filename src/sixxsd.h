/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2013 All Rights Reserved
***********************************************************/

#ifndef SIXXSD_H
#define SIXXSD_H "The Daemon Of SixXS"

/* How much is a clock allowed to be off? */
#define MAX_CLOCK_OFF		120

/* How many tunnels does a single sixxsd support? */
#define SIXXSD_TUNNELS_MAX	8192

/* The maximum number of PoPs (2**6) */
#define SIXXSD_POP_MAX		64

#define POPNAME ((g_conf->pop_id >= SIXXSD_POP_MAX) ? "notconf" : g_conf->pops[g_conf->pop_id].name)

/* First 4 bits */
#define TOFOUR_ISPFX(a) 	((a >> 28) != 0xf)

/* Bits 4 - 9 (6 total) */
#define TOFOUR_POPID(a)		((a >> 22) & 0x3f)

/* Selector is the last 22 bits, hence big numbers */
#define TOFOUR_SELECTOR(a)	(          a &  0x3fffff)

/* First 7 bits of 22 bits set */
#define TOFOUR_SEL_IS_TUN(a)	(          a >= 0x3f8000)

#define TOFOUR_SEL_TUN_TUNID(a)	((a >> 1) & 0x3fff)
#define TOFOUR_SEL_SUB_TUNID(a) ((a >> 8) & 0x3fff)
#define TOFOUR_SEL_TUNID(a) (TOFOUR_SEL_IS_TUN(a) ? TOFOUR_SEL_TUN_TUNID(a) : TOFOUR_SEL_SUB_TUNID(a))

#define IPV4_INIT(ip, len, proto) {		\
	ip.ip_v = 4;				\
        ip.ip_hl = sizeof(ip)/4;		\
        ip.ip_tos = 0;				\
        ip.ip_len = htons(len);			\
        ip.ip_id = 0x42;			\
        ip.ip_off = htons(IP_DF);		\
        ip.ip_ttl = 64;				\
        ip.ip_p = proto;			\
	}

#define IPV6_INIT(ip, len, proto) {				\
	ip.ip6_ctlun.ip6_un1.ip6_un1_flow = htons(0);		\
	ip.ip6_ctlun.ip6_un2_vfc = (6 << 4);			\
	ip.ip6_ctlun.ip6_un1.ip6_un1_plen = htons(len);		\
	ip.ip6_ctlun.ip6_un1.ip6_un1_hlim = 64;			\
	ip.ip6_ctlun.ip6_un1.ip6_un1_nxt = proto;		\
	}

#define IPV6_VER(ip) (ip->ip6_ctlun.ip6_un2_vfc >> 4)
#define IS_IPV6(ip6) (IPV6_VER(ip6) == 6)
#define SS_IPV6_SRC(ss) &(((struct sockaddr_in6 *)ss)->sin6_addr)
#define SS_IPV6_ADDR(ss) ((IPADDRESS *)SS_IPV6_SRC(ss))
#define SS_IPV4_SRC(ss) &(((struct sockaddr_in *)ss)->sin_addr)

#include "platform.h"

/* List Code */
#include "list.h"

/* Read/Write Lock */
#include "rwl.h"

/* Used almost everywhere thus define it like this */
struct sixxsd_context;

#include "common_extra.h"

/* Context */
#include "context.h"

/* Hashes */
#include "hash_sha1.h"
#include "hash_md5.h"

/* Checksum */
#include "checksum.h"

/* Stats */
#include "stats.h"

/* Subnets */
#include "subnet.h"

/* Tunnels */
#include "tunnel.h"

/* Port Proxy */
#include "pproxy.h"

/* Config */
#include "config.h"

/* Interfaces */
#include "iface.h"

/* Common code */
#include "common.h"

/* Thread Management */
#include "thread.h"

/* sixxsd.c */
VOID terminate(const char *who);

/* Protocols */
#include "ayiya.h"
#include "direct.h"
#include "gre.h"
#include "hb.h"
#include "icmpv4.h"

BOOL l3_ipv6_parse(const uint16_t in_tid, const uint16_t out_tid,
                   const uint8_t *packet, const uint32_t len,
                   uint8_t *_payload_type, uint8_t **_payload, uint32_t *_plen);

BOOL l3_ipv4_parse(const uint16_t in_tid, const uint16_t out_tid,
                   const uint8_t *packet, const uint32_t len,
                   uint8_t *_payload_type, uint8_t **_payload, uint32_t *_plen);

#endif /* SIXXSD_H */

