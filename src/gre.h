/**********************************************************
 SixXSd - SixXS PoP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2013 All Rights Reserved
**********************************************************/

#ifndef GRE_H
#define GRE_H "GRE (RFC2784)"

#include "sixxsd.h"

VOID gre_in(const IPADDRESS *src, uint16_t protocol, uint8_t *packet, const uint16_t len);
VOID gre_out_ipv4(struct sixxsd_tunnel *tun, const uint16_t in_tid, const uint16_t out_tid, const uint8_t protocol, const uint8_t *packet, const uint16_t len, BOOL is_response);
VOID gre_out_ipv6(struct sixxsd_tunnel *tun, const uint16_t in_tid, const uint16_t out_tid, const uint8_t protocol, const uint8_t *packet, const uint16_t len, BOOL is_response);

#endif

