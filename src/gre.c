/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2013 All Rights Reserved
************************************************************
 Generic Routing Encapsulation (GRE) - RFC2784 - proto-47
***********************************************************/
#include "sixxsd.h"

const char module_gre[] = "gre";
#define module module_gre

VOID gre_out_ipv4(struct sixxsd_tunnel *tun, const uint16_t in_tid, const uint16_t out_tid, const uint8_t protocol, const uint8_t *packet, const uint16_t len, BOOL is_response)
{
	struct
	{
		struct ip	ip;
		struct grehdr	gre;
	} PACKED pkt;

	memzero(&pkt, sizeof(pkt));

	/* IP version 4 */
	IPV4_INIT(pkt.ip, sizeof(pkt) + len, IPPROTO_GRE);

	/* Fill in the IP header from the original packet, swapping source & dest */
	memcpy(&pkt.ip.ip_src, ipaddress_ipv4(&g_conf->pops[g_conf->pop_id].ipv4),sizeof(pkt.ip.ip_src));
	memcpy(&pkt.ip.ip_dst, ipaddress_ipv4(&tun->ip_them),			sizeof(pkt.ip.ip_dst));

	/* GRE is mostly zeros, even the version number */
	pkt.gre.proto = ntohs(protocol == IPPROTO_IPV4 ? ETHERTYPE_IP : ETHERTYPE_IPV6);

	iface_send4(in_tid, out_tid, (const uint8_t *)&pkt, sizeof(pkt), packet, len, is_response, packet, len);
}

VOID gre_out_ipv6(struct sixxsd_tunnel *tun, const uint16_t in_tid, const uint16_t out_tid, const uint8_t protocol, const uint8_t *packet, const uint16_t len, BOOL is_response)
{
	struct
	{
		struct ip6_hdr		ip;
		struct grehdr		gre;
		uint8_t			payload[2048];
	} PACKED			pkt;

        /* IPv6 */
	IPV6_INIT(pkt.ip, len, protocol);

        memcpy(&pkt.ip.ip6_src, &g_conf->pops[g_conf->pop_id].ipv6,	sizeof(pkt.ip.ip6_src));
        memcpy(&pkt.ip.ip6_dst, &tun->ip_them,				sizeof(pkt.ip.ip6_dst));

	/* GRE is mostly zeros, even the version number */
	pkt.gre.proto = ntohs(protocol == IPPROTO_IPV4 ? ETHERTYPE_IP : ETHERTYPE_IPV6);

	memcpy(pkt.payload, packet, len);

	/* Send it off: maybe an error, don't decrease the TTL, don't check the source */
        iface_route6(in_tid, out_tid, (uint8_t *)&pkt, sizeof(pkt) - sizeof(pkt.payload) + len, is_response, false, true);
}

VOID gre_in(const IPADDRESS *src, uint16_t protocol, uint8_t *packet, const uint16_t len)
{
	struct ip		*ip4 = (struct ip *)packet;
	struct ip6_hdr		*ip6 = (struct ip6_hdr *)packet;
	struct sixxsd_tunnel	*tun;
	uint16_t		in_tid;
	BOOL			istunnel, fail = false;
	uint16_t		code = 0;

	/*
	 * Fetch it. This automatically does RPF as we use the source IPv6 address for
         * determining the associated tunnel.
	 * It also nicely solves the problem of having to search for the IPv4 src/dst pair :)
	 */
	if (protocol == AF_INET6)
	{
		in_tid = address_find6((IPADDRESS *)&ip6->ip6_src, &istunnel);
	}
	else
	{
		in_tid = address_find4((IPADDRESS *)&ip4->ip_src, &istunnel);
	}

	tun = (in_tid == SIXXSD_TUNNEL_UPLINK ? NULL : tunnel_grab(in_tid));

	if (!tun || tun->state == SIXXSD_TSTATE_NONE)
	{
		code = ICMP_PROT_UNREACH;
		fail = true;
	}

	else if (tun->type != SIXXSD_TTYPE_DIRECT && tun->type != SIXXSD_TTYPE_DIRECT_HB)
	{
		code = ICMP_PKT_FILTERED;
		fail = true;
	}

	/* Verify that the sender is the real endpoint of this packet */
	else if (memcmp(src, &tun->ip_them, sizeof(*src)) != 0)
	{
		code = ICMP_PROT_UNREACH;
		fail = true;
	}

	if (fail)
	{
		/* Reconstruct the original packet */
		struct
		{
			struct ip	ip;
			uint8_t		payload[1480];
		}			pkt;
		uint16_t		plen;

		plen = len > sizeof(pkt.payload) ? sizeof(pkt.payload) : len;

		/* IP version 4 */
		IPV4_INIT(pkt.ip, sizeof(pkt.ip) + plen, IPPROTO_IPV6);

		/* Fill in the IP header from the original packet, swapping source & dest */
		memcpy(&pkt.ip.ip_src, ipaddress_ipv4(src),				sizeof(pkt.ip.ip_src));
		memcpy(&pkt.ip.ip_dst, ipaddress_ipv4(&g_conf->pops[g_conf->pop_id].ipv4),	sizeof(pkt.ip.ip_dst));

		/* The payload */
		memcpy(&pkt.payload, packet, plen);

		/* Calculate the IP checksum */
		pkt.ip.ip_sum = htons(0);
		pkt.ip.ip_sum = in_checksum((unsigned char *)&pkt, sizeof(pkt.ip));

		iface_send_icmpv4_unreach(in_tid, SIXXSD_TUNNEL_NONE, (uint8_t *)&pkt, sizeof(pkt.ip) + plen, code);
		return;
	}

	if (!tunnel_state_check(in_tid, SIXXSD_TUNNEL_NONE, packet, len, false)) return;

	/* Account the packet */
	tunnel_account_packet_in(in_tid, len);

	/* Forward it: it is not an error, do decrease the TTL, do check the source */
	iface_route6(in_tid, SIXXSD_TUNNEL_NONE, packet, len, false, true, false);
}

