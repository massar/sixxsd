/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2013 All Rights Reserved
***********************************************************/

#ifndef IFACE_H
#define IFACE_H "Interface"

int iface_init				(struct sixxsd_context *ctx);
int iface_exit				(struct sixxsd_context *ctx);
VOID iface_upnets			(VOID);
VOID iface_route6			(const uint16_t in_tid, const uint16_t out_tid, uint8_t *packet, const uint16_t len, BOOL is_response, BOOL decrease_ttl, BOOL nosrcchk);
VOID iface_route4			(const uint16_t in_tid, const uint16_t out_tid, uint8_t *packet, const uint16_t len, BOOL is_response, BOOL decrease_ttl, BOOL nosrcchk);
VOID iface_send4			(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *header, const uint16_t header_len, const uint8_t *packet, const uint16_t packet_len, BOOL is_response, const uint8_t *orgpacket, const uint16_t orgpacket_len);
VOID iface_send_icmpv6			(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, const uint8_t type, const uint8_t code, const uint32_t param, struct in6_addr *dst);
VOID iface_send_icmpv6_unreach		(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, const uint8_t code);
VOID iface_send_icmpv4_unreach		(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, const uint8_t code);
VOID iface_send_icmpv6_ttl		(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len);
VOID iface_send_icmpv4_ttl		(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len);
VOID iface_send_icmpv6_toobig		(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, const uint16_t mtu);
VOID iface_send_icmpv4_toobig		(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, const uint16_t mtu);
VOID iface_send_icmp_toobig		(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, const uint16_t mtu);
VOID iface_send_icmpv6_echo_reply	(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len);
VOID iface_send_icmpv6_neigh		(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len);

uint16_t address_find			(IPADDRESS *addr, BOOL *istunnel);

#endif /* IFACE_H */

