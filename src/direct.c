/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2013 All Rights Reserved
************************************************************
 Protocol 4 + 41 - RFC2303 + RFC2473
***********************************************************/
#include "sixxsd.h"

const char module_direct[] = "direct";
#define module module_direct

VOID direct_out_ipv4(struct sixxsd_tunnel *tun, const uint16_t in_tid, const uint16_t out_tid, const uint8_t protocol, const uint8_t *packet, const uint16_t len, BOOL is_response)
{
	struct ip ip;

	/* IP version 4 */
	IPV4_INIT(ip, sizeof(ip) + len, protocol);

	/* Fill in the IP header from the original packet, swapping source & dest */
	memcpy(&ip.ip_src, ipaddress_ipv4(&tun->ip_us),		sizeof(ip.ip_src));
	memcpy(&ip.ip_dst, ipaddress_ipv4(&tun->ip_them),	sizeof(ip.ip_dst));

	iface_send4(in_tid, out_tid, (const uint8_t *)&ip, sizeof(ip), packet, len, is_response, packet, len);
}

VOID direct_out_ipv6(struct sixxsd_tunnel *tun, const uint16_t in_tid, const uint16_t out_tid, const uint8_t protocol, const uint8_t *packet, const uint16_t len, BOOL is_response)
{
	struct
	{
		struct ip6_hdr		ip;
		uint8_t			payload[2048];
	} PACKED			pkt;

        /* IPv6 */
	IPV6_INIT(pkt.ip, len, protocol);

        memcpy(&pkt.ip.ip6_src, &tun->ip_us,	sizeof(pkt.ip.ip6_src));
        memcpy(&pkt.ip.ip6_dst, &tun->ip_them,	sizeof(pkt.ip.ip6_dst));

	memcpy(pkt.payload, packet, len);

	/* Send it off: maybe an error, don't decrease the TTL, don't check the source */
        iface_route6(in_tid, out_tid, (uint8_t *)&pkt, sizeof(pkt) - sizeof(pkt.payload) + len, is_response, false, true);
}

VOID direct_in(const IPADDRESS *src, const IPADDRESS *dst, uint16_t packettype, uint8_t *packet, const uint16_t len, uint16_t protocol, uint8_t *payload, uint16_t plen, enum sixxsd_tunnel_type ttype)
{
	struct ip6_hdr		*ip6 = (struct ip6_hdr *)payload;
	struct ip		*ip4 = (struct ip *)payload;
	struct sixxsd_tunnel	*tun;
	uint16_t		code = 0;
	BOOL			fail = false;
	BOOL			istunnel;
	uint16_t		in_tid;

	/*
	 * Fetch it. This automatically does RPF as we use the source inner IP address for
         * determining the associated tunnel.
	 * It also nicely solves the problem of having to search for the IPv4 src/dst pair :)
	 */
	if (protocol == IPPROTO_IPV6)
	{
		in_tid = address_find6((IPADDRESS *)&ip6->ip6_src, &istunnel);
	}
	else
	{
		in_tid = address_find4((IPADDRESS *)&ip4->ip_src, &istunnel);
	}

	tun = (in_tid == SIXXSD_TUNNEL_UPLINK ? NULL : tunnel_grab(in_tid));

	/* Unconfigured tunnels */
	if (!tun || tun->state == SIXXSD_TSTATE_NONE)
	{
		code = ICMP_PROT_UNREACH;
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
		if (packettype == IPPROTO_IPV6)
		{
			iface_send_icmpv6_unreach(in_tid, SIXXSD_TUNNEL_NONE, packet, len, code);
		}
		else
		{
			iface_send_icmpv4_unreach(in_tid, SIXXSD_TUNNEL_NONE, packet, len, code);
		}
		return;
	}

	if (!tunnel_state_check(in_tid, SIXXSD_TUNNEL_NONE, payload, plen, false)) return;

	/*
	 * Change tunnel type based on last packet received
	 * This thus swaps between DIRECT and GRE automatically
	 */
	tun->type = ttype;

	/* What is our side of the tunnel? */
	memcpy(&tun->ip_us, dst, sizeof(tun->ip_us));

	/* Account the packet */
	tunnel_account_packet_in(in_tid, plen);

	/* Forward it: it is not an error, do decrease the TTL, do check the source */
	if (protocol == IPPROTO_IPV6)
	{
		iface_route6(in_tid, SIXXSD_TUNNEL_NONE, payload, plen, false, true, false);
	}
	else
	{
		iface_route4(in_tid, SIXXSD_TUNNEL_NONE, payload, plen, false, true, false);
	}
}

