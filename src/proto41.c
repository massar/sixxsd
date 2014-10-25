/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2013 All Rights Reserved
************************************************************
 Heartbeat
***********************************************************/
#include "sixxsd.h"

const char module_proto41[] = "proto41";
#define module module_proto41

static VOID p41_log(int level, const IPADDRESS *src, const char *ATTR_RESTRICT fmt, ...) ATTR_FORMAT(printf, 3, 4);
static VOID p41_log(int level, const IPADDRESS *src, const char *fmt, ...)
{
	char	buf[1024];
	char	srca[NI_MAXHOST];
	va_list	ap;

	inet_ntopA(src, srca, sizeof(srca));

	/* Print the log message behind it */
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	
	/* Actually Log it */
	mdolog(level, "[%s]: %s", srca, buf);
}

VOID proto41_out(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, BOOL is_response)
{
	struct sixxsd_tunnel	*tun = tunnel_grab(out_tid);
	struct ip		ip;

	if (!tun)
	{
		if (!is_response) iface_send_icmpv4_unreach(in_tid, out_tid, packet, len, ICMP_PROT_UNREACH);
		return;
	}

	if (len > tun->mtu)
	{
		tunnel_log(in_tid, out_tid, packet,len, SIXXSD_TERR_TUN_ENCAPS_PACKET_TOO_BIG, &tun->ip_them);
		if (!is_response) iface_send_icmp_toobig(in_tid, out_tid, packet, len, tun->mtu);
		return;
	}

	if (!tunnel_state_check(in_tid, out_tid, packet, len, is_response)) return;

	/* IP version 4 */
	ip.ip_v = 4;
	ip.ip_hl = sizeof(ip) / 4;
	ip.ip_tos = 0;
	ip.ip_len = htons(sizeof(ip) + len);
	ip.ip_id = 0x42;
	ip.ip_off = htons(IP_DF);
	ip.ip_ttl = 64;
	ip.ip_p = IPPROTO_IPV6;

	/* Fill in the IP header from the original packet, swapping source & dest */
	memcpy(&ip.ip_src, ipaddress_ipv4(&g_conf->pops[g_conf->pop_id].ipv4),	sizeof(ip.ip_src));
	memcpy(&ip.ip_dst, ipaddress_ipv4(&tun->ip_them),			sizeof(ip.ip_dst));

	iface_send4(in_tid, out_tid, (const uint8_t *)&ip, sizeof(ip), packet, len, is_response, packet, len);
}

VOID proto41_in(const IPADDRESS *src, uint8_t *packet, const uint16_t len)
{
	struct ip6_hdr		*ip = (struct ip6_hdr *)packet;
	struct sixxsd_tunnel	*tun;
	uint16_t		in_tid;
	BOOL			istunnel, fail = false;
	uint16_t		code = 0;

	/* Quick sanity check */
	if (len < sizeof(*ip))
	{
		p41_log(LOG_WARNING, src, "Short IPv6 packet received of len %u\n", len);
		return;
	}

	/* Unspecified or link-local address? */
	if (IN6_IS_ADDR_UNSPECIFIED(&ip->ip6_src) ||
	    IN6_IS_ADDR_LINKLOCAL(&ip->ip6_src))
	{
		/*
		 * Just ignore the packet, as long we don't do multicast it does not matter.
		 *
		 * But if we would process it further it would generate an proto-41
		 * unreachable as then the source address could not be found.
		 */
		return;
	}

	/*
	 * Fetch it. This automatically does RPF as we use the source IPv6 address for
         * determining the associated tunnel.
	 * It also nicely solves the problem of having to search for the IPv4 src/dst pair :)
	 */
	in_tid = address_find((IPADDRESS *)&ip->ip6_src, &istunnel);
	tun = in_tid == SIXXSD_TUNNEL_UPLINK ? NULL : tunnel_grab(in_tid);

	if (!tun || tun->state == SIXXSD_TSTATE_NONE)
	{
		code = ICMP_PROT_UNREACH;
		fail = true;
	}

	else if (tun->type != SIXXSD_TTYPE_PROTO41 && tun->type != SIXXSD_TTYPE_PROTO41_HB)
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
		pkt.ip.ip_v = 4;
		pkt.ip.ip_hl = sizeof(pkt.ip) / 4;
		pkt.ip.ip_tos = 0;
		pkt.ip.ip_len = htons(sizeof(pkt.ip) + plen);
		pkt.ip.ip_id = 0x42;
		pkt.ip.ip_off = htons(IP_DF);
		pkt.ip.ip_ttl = 64;
		pkt.ip.ip_p = IPPROTO_IPV6;

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

	if ((ip->ip6_ctlun.ip6_un2_vfc >> 4) != 6)
	{
		tunnel_log(SIXXSD_TUNNEL_NONE, in_tid, packet, len, SIXXSD_TERR_TUN_PAYLOAD_NOT_IPV6, src);
		return;
	}

	/* Account the packet */
	tunnel_account_packet_in(in_tid, len);

	/* Forward it: it is not an error, do decrease the TTL, do check the source */
	iface_route6(in_tid, SIXXSD_TUNNEL_NONE, packet, len, false, true, false);
}

