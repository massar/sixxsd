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

VOID gre_in(const IPADDRESS *src, uint16_t packettype, uint8_t *packet, const uint16_t len, uint8_t *payload, uint16_t plen)
{
	struct grehdr		*gre;
	uint16_t		protocol;
	BOOL			fail = false;

	/* Check the GRE header */
	gre = (struct grehdr *)payload;

	/* RFC2303 only handles version 0 */
	if (gre->version != 0)
	{
		fail = true;
	}

	/* Which protocol is embedded? */
	protocol = ntohs(gre->proto);

	switch (protocol)
	{
	case ETH_P_IP:
		protocol = IPPROTO_IPV4;
		break;

	case ETH_P_IPV6:
		protocol = IPPROTO_IPV6;
		break;

	default:
		fail = true;
	}

	if (fail)
	{
		/* Unknown protocol, reject it */
		if (packettype == IPPROTO_IPV6)
		{
			iface_send_icmpv6_unreach(SIXXSD_TUNNEL_UPLINK, SIXXSD_TUNNEL_NONE, packet, len, ICMP_PROT_UNREACH);
		}
		else
		{
			iface_send_icmpv4_unreach(SIXXSD_TUNNEL_UPLINK, SIXXSD_TUNNEL_NONE, packet, len, ICMP_PROT_UNREACH);
		}
		return;
	}

	if ((gre->chksum_present >> 7) == 1)
	{
		/* Checksum is present */
		payload = &payload[8];
		plen = len - 8;
	}
	else
	{
		/* Checksum is not present */
		payload = &payload[4];
		plen = len - 4;
	}

	/* Let the direct code handle the rest */
	direct_in(src, packettype, packet, len, protocol, payload, plen, SIXXSD_TTYPE_GRE);
}

