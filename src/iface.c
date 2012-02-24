/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2012 All Rights Reserved
***********************************************************/

#include "sixxsd.h"

const char module_iface[] = "iface";
#define module module_iface

struct pingtest
{
	uint64_t	time_us;
	uint64_t	magic;
	uint8_t		message[1000];
};

static VOID os_exec(const char *fmt, ...) ATTR_FORMAT(printf,1,2);
static VOID os_exec(const char *fmt, ...)
{
        char	buf[1024];
        va_list	ap;

        va_start(ap, fmt);
        vsnprintf(buf, sizeof(buf), fmt, ap);
        mdolog(LOG_DEBUG, "#### os_exec(\"%s\")\n", buf);
        system(buf);
        va_end(ap);
}

static const char *iface_socket_name(enum sixxsd_sockets type);
static const char *iface_socket_name(enum sixxsd_sockets type)
{
	switch (type)
	{
	case SIXXSD_SOCK_TUNTAP:
		return "Tun/Tap";

	case SIXXSD_SOCK_PROTO41:
		return "Protocol-41";

	case SIXXSD_SOCK_AYIYA:
		return "AYIYA";

	case SIXXSD_SOCK_HB:
		return "Heartbeat";

	default:
		break;
	}

	assert(false);
	return "unknown";
}

static VOID iface_sendtap(const uint16_t in_tid, const uint16_t out_tid, uint16_t protocol, const uint8_t *packet, const uint16_t packet_len, BOOL is_error, const uint8_t *orgpacket, const uint16_t orgpacket_len);
static VOID iface_sendtap(const uint16_t in_tid, const uint16_t out_tid, uint16_t protocol, const uint8_t *packet, const uint16_t packet_len, BOOL is_error, const uint8_t *orgpacket, const uint16_t org_len)
{
	int		n;
	unsigned int	iovlen = 0;
	struct iovec	iov[3];
#ifdef _LINUX
	struct tun_pi	pi;

	pi.flags = htons(0);
	pi.proto = htons(protocol);

	memzero(iov, sizeof(iov));
	iov[iovlen].iov_base = &pi;
	iov[iovlen].iov_len  = sizeof(pi);

#else /* BSD */
	uint32_t type = htonl(protocol == ETH_P_IP ? AF_INET : AF_INET6);

	memzero(iov, sizeof(iov));
	iov[iovlen].iov_base = (void *)&type;
	iov[iovlen].iov_len  = sizeof(type);
#endif
	iovlen++;

	assert(packet && packet_len != 0);

	iov[iovlen].iov_base = (char *)packet;
	iov[iovlen].iov_len  = packet_len;
	iovlen++;

#ifdef DEBUG
	if ((packet[0] >> 4) != (protocol == ETH_P_IP ? 4 : 6))
	{
		assert(false);
	}
#endif

	/* Send the packet to our tun/tap device and let the kernel handle it for the rest */
	n = writev(g_conf->tuntap, iov, iovlen);

	if (n >= 0)
	{
		tunnel_account_packet_out(out_tid, packet_len);
		return;
	}

	switch (errno)
	{
	case EMSGSIZE:
		tunnel_log(in_tid, out_tid, SIXXSD_TERR_TUN_ENCAPS_PACKET_TOO_BIG, NULL);
		break;
	default:
		tunnel_log(in_tid, out_tid, SIXXSD_TERR_TUN_ENCAPS_OUT_ERR, NULL);
		break;
	}

	if (is_error) return;

	if (protocol == ETH_P_IPV6) iface_send_icmpv6_unreach(in_tid, out_tid, orgpacket, org_len, ICMP6_DST_UNREACH_ADMIN);
	else iface_send_icmpv4_unreach(in_tid, out_tid, orgpacket, org_len, ICMP_PKT_FILTERED);
}

VOID iface_send4(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *header, const uint16_t header_len, const uint8_t *packet, const uint16_t packet_len, BOOL is_error, const uint8_t *orgpacket, const uint16_t orgpacket_len)
{
	struct ip		*ip = (struct ip *)header;
	int			n;
	struct iovec		iov[2];
	unsigned int		iovlen = 0;
	struct msghdr		msg;
	struct sockaddr_in	dst;

	memzero(iov, sizeof(iov));
	memzero(&dst, sizeof(dst));
	dst.sin_family = AF_INET;
	memcpy(&dst.sin_addr, &ip->ip_dst, sizeof(dst.sin_addr));

#ifdef _LINUX
	/* Update the checksum */
	ip->ip_sum = htons(0);
	ip->ip_sum = in_checksum((unsigned char *)ip, sizeof(*ip));

	assert((packet && packet_len > 0) || (!packet && packet_len == 0));

	iov[iovlen].iov_base = (char *)header;
	iov[iovlen].iov_len  = header_len;
	iovlen++;
#else
	/* For FreeBSD, skip the IPv4 header */
	if (header_len > 20)
	{
		iov[iovlen].iov_base = (char *)&header[20];
		iov[iovlen].iov_len  = header_len - 20;
		iovlen++;
	}
#endif

	if (packet)
	{
		iov[iovlen].iov_base = (char *)packet;
		iov[iovlen].iov_len  = packet_len;
		iovlen++;
	}

	memzero(&msg, sizeof(msg));
	msg.msg_name		= &dst;
	msg.msg_namelen		= sizeof(dst);
	msg.msg_iov		= iov;
	msg.msg_iovlen		= iovlen;
	msg.msg_control		= NULL;
	msg.msg_controllen	= 0;
	msg.msg_flags		= 0;

	/* Send the packet and let the kernel handle it for the rest */
#ifdef _LINUX
	n = sendmsg(g_conf->rawsocket_ipv4, &msg, MSG_NOSIGNAL);
#else
	/*
	 * On FreeBSD we apparently cannot do sendmsg() and include
	 * a header even if we set HDRINCL on, as such use two separate
	 * sockets: one for proto-41 and one for ICMP.
	 * This also means that other protocols are not supported.
	 * And if we ever send those they will be dropped...
	 */
	switch (ip->ip_p)
	{
	case IPPROTO_IPV6:
		n = sendmsg(g_conf->rawsocket_proto41, &msg, MSG_NOSIGNAL);
		break;
	case IPPROTO_ICMP:
		n = sendmsg(g_conf->rawsocket_ipv4, &msg, MSG_NOSIGNAL);
		break;
	default:
		tunnel_debug(in_tid, out_tid, packet, packet_len, "send4 unknown proto %u\n", ip->ip_p);
		return;
	}
#endif
	if (n >= 0)
	{
		tunnel_account_packet_out(out_tid, header_len + packet_len);
		return;
	}

	switch (errno)
	{
	case EMSGSIZE:
		tunnel_log4(in_tid, out_tid, SIXXSD_TERR_TUN_ENCAPS_PACKET_TOO_BIG, &ip->ip_dst);
		break;
	default:
		tunnel_debug(in_tid, out_tid, packet, packet_len, "send4 (%u) error %u\n", ip->ip_p, errno);
		tunnel_log4(in_tid, out_tid, SIXXSD_TERR_TUN_ENCAPS_OUT_ERR, &ip->ip_dst);
		break;
	}

	if (!is_error) iface_send_icmpv4_unreach(in_tid, out_tid, orgpacket, orgpacket_len, ICMP_PKT_FILTERED);
}

static BOOL iface_prepfwd4(const uint16_t in_tid, const uint16_t out_tid, uint8_t *packet, const uint16_t len, BOOL is_error, BOOL decrease_ttl);
static BOOL iface_prepfwd4(const uint16_t in_tid, const uint16_t out_tid, uint8_t *packet, const uint16_t len, BOOL is_error, BOOL decrease_ttl)
{
	struct ip		*ip = (struct ip *)packet;
	struct sixxsd_tunnel	*outtun = (out_tid != SIXXSD_TUNNEL_NONE && out_tid != SIXXSD_TUNNEL_UPLINK) ? tunnel_grab(out_tid) : NULL;

	/* First check if the packet can actually go out over that output */
	if (outtun && len > outtun->mtu)
	{
		tunnel_log4(in_tid, out_tid, SIXXSD_TERR_TUN_ENCAPS_PACKET_TOO_BIG, &ip->ip_src);
		if (!is_error) iface_send_icmpv4_toobig(in_tid, out_tid, packet, len, outtun->mtu);
		return false;
	}

	tunnel_debug(in_tid, out_tid, packet, len, "IPv4 TTL: %u\n", ip->ip_ttl);

	/* Just drop it */
	if (ip->ip_ttl == 0) return false;

	/* Out of hops? */
	if (ip->ip_ttl <= 1)
	{
		if (!is_error) iface_send_icmpv4_ttl(in_tid, out_tid, packet, len);
		return false;
	}

	if (decrease_ttl) ip->ip_ttl--;

	/* In IPv4 one has to recalculate the checksum at every hop */
	ip->ip_sum = htons(0);
	ip->ip_sum = in_checksum(packet, sizeof(*ip));

	return true;
}

static BOOL iface_prepfwd6(const uint16_t in_tid, const uint16_t out_tid, uint8_t *packet, const uint16_t len, BOOL is_error, BOOL decrease_ttl);
static BOOL iface_prepfwd6(const uint16_t in_tid, const uint16_t out_tid, uint8_t *packet, const uint16_t len, BOOL is_error, BOOL decrease_ttl)
{
	struct ip6_hdr		*ip6 = (struct ip6_hdr *)packet;
	struct sixxsd_tunnel	*outtun = (out_tid != SIXXSD_TUNNEL_NONE && out_tid != SIXXSD_TUNNEL_UPLINK) ? tunnel_grab(out_tid) : NULL;

	tunnel_debug(in_tid, out_tid, packet, len, "IPv6 PrepFwd6 %u\n", len);

	/* First check if the packet can actually go out over that output */
	if (outtun && len > outtun->mtu)
	{
		tunnel_debug(in_tid, out_tid, packet, len, "prepfwd6 %04x to %04x len = %u > mtu = %u\n", in_tid, out_tid, len, outtun->mtu);
		tunnel_log(in_tid, out_tid, SIXXSD_TERR_TUN_ENCAPS_PACKET_TOO_BIG, (IPADDRESS *)&ip6->ip6_src);
		if (!is_error) iface_send_icmpv6_toobig(in_tid, out_tid, packet, len, outtun->mtu);
		return false;
	}

	tunnel_debug(in_tid, out_tid, packet, len, "IPv6 HopLimit: %u\n", ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim);

	/* Just drop it */
	if (ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim == 0)
	{
		tunnel_debug(in_tid, out_tid, packet, len, "HopLimit == 0 -> dropping it\n");
		return false;
	}

	/* Out of hops? */
	if (ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim <= 1)
	{
		tunnel_debug(in_tid, out_tid, packet, len, "HopLimit <= 1\n");
		if (!is_error) iface_send_icmpv6_ttl(in_tid, out_tid, packet, len);
		return false;
	}

	if (decrease_ttl)
	{
		ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim--;
		tunnel_debug(in_tid, out_tid, packet, len, "IPv6 HopLimit New %u\n", ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim);
	}

	return true;
}

/* Send appropriate ICMP unreachables */
static VOID iface_unreachtun(const uint16_t in_tid, const uint16_t out_tid, const uint8_t protocol, const uint8_t *packet, const uint16_t len, BOOL is_error);
static VOID iface_unreachtun(const uint16_t in_tid, const uint16_t out_tid, const uint8_t protocol, const uint8_t *packet, const uint16_t len, BOOL is_error)
{
	struct sixxsd_tunnel	*outtun = tunnel_grab(out_tid);
	uint8_t			code4 = ICMP_NET_UNREACH, code6 = ICMP6_DST_UNREACH_ADDR;

	/* Need a tunnel here */
	if (!outtun) return;

	/* Don't reply to ICMP errors */
	if (is_error) return;

	/* Interface must be 'up' for it to work */
	switch (outtun->state)
	{
	case SIXXSD_TSTATE_UP:
		/* Should be handled by caller */
		assert(false);
		break;

	case SIXXSD_TSTATE_DISABLED:
		code4 = ICMP_PKT_FILTERED;
		code6 = ICMP6_DST_UNREACH_ADMIN;
		break;

	case SIXXSD_TSTATE_DOWN:
		code4 = ICMP_NET_UNREACH;
		code6 = ICMP6_DST_UNREACH_NOROUTE;
		break;

	case SIXXSD_TSTATE_NONE:
	default:
		code4 = ICMP_NET_UNREACH;
		code6 = ICMP6_DST_UNREACH_ADDR;
		break;
	}

	if (protocol == IPPROTO_IP)	iface_send_icmpv4_unreach(in_tid, out_tid, packet, len, code4);
	else				iface_send_icmpv6_unreach(in_tid, out_tid, packet, len, code6);
}

static VOID iface_routetun(const uint16_t in_tid, const uint16_t out_tid, const uint8_t protocol, const uint8_t *packet, const uint16_t len, BOOL is_error);
static VOID iface_routetun(const uint16_t in_tid, const uint16_t out_tid, const uint8_t protocol, const uint8_t *packet, const uint16_t len, BOOL is_error)
{
	struct sixxsd_tunnel	*outtun = tunnel_grab(out_tid);

	assert(protocol == IPPROTO_IP || protocol == IPPROTO_IPV6);

	tunnel_debug(in_tid, out_tid, packet, len, "iface_routetun() kicking it out%s\n", is_error ? " [error]" : " [normal]");

	/* No way to get out */
	if (!outtun)
	{
		if (!is_error)
		{
			if (protocol == IPPROTO_IP)	iface_send_icmpv4_unreach(in_tid, out_tid, packet, len, ICMP_NET_UNREACH);
			else				iface_send_icmpv6_unreach(in_tid, out_tid, packet, len, ICMP6_DST_UNREACH_ADDR);
		}

		return;
	}

	/* Same input as output? */
	if (!is_error && in_tid == out_tid)
	{
		if (protocol == IPPROTO_IP)
		{
			struct ip *ip = (struct ip *)packet;
			tunnel_log4(in_tid, out_tid, SIXXSD_TERR_TUN_SAME_IO, &ip->ip_src);
		}
		else
		{
			struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;
			tunnel_log(in_tid, out_tid, SIXXSD_TERR_TUN_SAME_IO, (IPADDRESS *)&ip6->ip6_src);
		}

		return;
	}

	if (outtun->state == SIXXSD_TSTATE_UP)
	{
		tunnel_debug(in_tid, out_tid, packet, len, "Tunnel up, forwarding to %s (%u)\n",
			(outtun->type == SIXXSD_TTYPE_PROTO41 ||
				outtun->type == SIXXSD_TTYPE_PROTO41_HB ? "proto41" : "ayiya"),
			outtun->type);

		switch (outtun->type)
		{
			case SIXXSD_TTYPE_PROTO41:
			case SIXXSD_TTYPE_PROTO41_HB:
				/* Can only send IPv6 inside of this */
				if (protocol == IPPROTO_IPV6)
				{
					proto41_out(in_tid, out_tid, packet, len, is_error);
					return;
				}

				/* Fall through to sending an unreachable below */
				break;

			case SIXXSD_TTYPE_AYIYA:
				ayiya_out(in_tid, out_tid, protocol, packet, len, is_error);
				return;

			default:
				assert(false);
				break;
		}
	}

	iface_unreachtun(in_tid, out_tid, protocol, packet, len, is_error);
}

/* Jeej, they reply to our ICMP echo requests! :) */
static VOID iface_got_icmpv6_reply(const uint16_t tid, uint8_t *packet, const uint16_t len, const struct icmp6_hdr *icmp, const uint16_t plen);
static VOID iface_got_icmpv6_reply(const uint16_t tid, uint8_t *packet, const uint16_t len, const struct icmp6_hdr *icmp, const uint16_t plen)
{
	struct sixxsd_tunnel	*tun;
	struct sixxsd_latency	*lat;
	struct pingtest		*d;
	uint64_t		currtime_us, t, seqbit;
	uint32_t		parm;
	uint16_t		seq;

	/* Should not happen... but you never ever know */
	tun = tunnel_grab(tid);
	if (!tun) return;

	lat = &tun->stats.latency;

	/* We expect at least this to come back */
	if (plen <= sizeof(*icmp) + sizeof(d->time_us) + 40)
	{
		tunnel_debug(tid, tid, packet, len, "Got short ICMPv6 packet, dropping it\n");
		return;
	}

	/* Check that the sequence number is sort of sane */
	parm = ntohl(icmp->icmp6_dataun.icmp6_un_data32[0]);
	if ((parm >> 16) != 0x4242)
	{
		tunnel_debug(tid, tid, packet, len, "ICMPv6 Echo Reply sequence number is not ours\n");
		return;
	}

	/* The sequence number from the packet */
	seq = parm & 0xffff;

	mutex_lock(g_conf->mutex_pinger);

	/*
	 * We keep in lat->seq the highest sequence number seen
	 * As such lat->seq_seen contains a bit each for the last 64 sequence numbers
	 * When we see one, we set it so we can detect resends.
	 */
	if (seq < (lat->seq - 64))
	{
		tunnel_debug(tid, tid, packet, len, "ICMPv6 Echo Reply Sequence Number %u out of range (%u-%u)\n", seq, lat->seq - 64, lat->seq);
		mutex_release(g_conf->mutex_pinger);
		return;
	}

	/* What is the bit that represents this sequence number? */
	seqbit = (1 >> (lat->seq - seq));

	/* Check if we have seen this sequence number already */
	if (lat->seq_seen & seqbit)
	{
		tunnel_debug(tid, tid, packet, len, "ICMPv6 Echo Reply Sequence Number %u was already seen\n", seq);
		mutex_release(g_conf->mutex_pinger);
		return;
	}

	d = (struct pingtest *)(((uint8_t *)(icmp)) + sizeof(*icmp));

	/* Check that the magic is either the current or the previous one */
	if (g_conf->magic[0] != d->magic && g_conf->magic[1] != d->magic)
	{
		tunnel_debug(tid, tid, packet, len, "ICMPv6 Echo Reply Magic is not current or previous\n");
		mutex_release(g_conf->mutex_pinger);
		return;
	}

	/*
	 * We deem the packet okay as the magic is correct and sequence is there
	 * Thus mark the packet as seen
	 */
	lat->seq_seen |= seqbit;

	/* How late is it now? */
	currtime_us = gettime_us();

	/* Back to the future is impossible */
	if (currtime_us < d->time_us)
	{
		tunnel_debug(tid, tid, packet, len, "ICMPv6 Echo Reply timestamp is in the future?\n");
		mutex_release(g_conf->mutex_pinger);
		return;
	}

	/* The latency incurred */
	t = currtime_us - d->time_us;

	/* Drop anything that comes in after 10.000 milliseconds == 10.000.000 microseconds */
	if (t > (10 * 1000 *1000))
	{
		tunnel_debug(tid, tid, packet, len, "ICMPv6 Echo Reply was %2.2f milliseconds old? (%" PRIu64 ", %" PRIu64 ", %" PRIu64 ")\n", time_us_msec(lat->min), t, currtime_us, d->time_us);
		mutex_release(g_conf->mutex_pinger);
		return;
	}

	if (lat->num_recv >= lat->num_sent)
	{
		tunnel_debug(tid, tid, packet, len, "Already received %u responses for %u sent packets...\n", lat->num_recv, lat->num_sent);
		mutex_release(g_conf->mutex_pinger);
		return;
	}

	/* Update min/max */
	if (t < lat->min) lat->min = t;
	if (t > lat->max) lat->max = t;

	lat->tot += t;
	lat->num_recv++;

	mutex_release(g_conf->mutex_pinger);
}

VOID iface_route6(const uint16_t in_tid, const uint16_t out_tid_, uint8_t *packet, const uint16_t len, BOOL is_error, BOOL decrease_ttl, BOOL nosrcchk)
{
	struct ip6_hdr		*ip6 = (struct ip6_hdr *)packet;
	uint16_t		out_tid = out_tid_;
	BOOL			istunnel;

	assert((is_error && !decrease_ttl) || !is_error);

	/* Make sure it is actually an IPv6 packet */
	if ((ip6->ip6_ctlun.ip6_un2_vfc >> 4) != 6)
	{
		tunnel_debug(in_tid, out_tid, packet, len, "iface_route6(%s) - dropping non-IPv6 packet (%u)\n", is_error ? "error" : "normal", ip6->ip6_ctlun.ip6_un2_vfc >> 4);
		return;
	}

	/* We might want to show every packet */
	tunnel_debug(in_tid, out_tid, packet, len, "iface_route6(%s/%s)\n", is_error ? "error" : "normal", nosrcchk ? "nosrcchk" : "srcchk");

	/* Ignore unspecified source (XXX: Check for IGMP listener / Multicast) */
	if (IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src))
	{
		tunnel_debug(in_tid, out_tid, packet, len, "iface_route6(%s) - dropping unspecified sourced packet\n", is_error ? "error" : "normal");
		return;
	}

	/* Ignore unspecified destination (XXX: Check for IGMP listener / Multicast) */
	if (IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_dst))
	{
		tunnel_debug(in_tid, out_tid, packet, len, "iface_route6(%s) - dropping unspecified destination packet\n", is_error ? "error" : "normal");
		return;
	}

	/* Ignore link-local source addresses */
	if (IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src))
	{
		tunnel_debug(in_tid, out_tid, packet, len, "iface_route6(%s) - dropping Link-local sourced packet\n", is_error ? "error" : "normal");
		return;
	}

	/* Ignore link-local destination addresses */
	if (IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_dst))
	{
		tunnel_debug(in_tid, out_tid, packet, len, "iface_route6(%s) - dropping Link-local destination packet\n", is_error ? "error" : "normal");
		return;
	}

	/* Do we want to check where this packet came from? */
	if (!nosrcchk)
	{
		/* Do we like the source address coming from this interface? */
		uint16_t src_tid = address_find((IPADDRESS *)&ip6->ip6_src, &istunnel);
		if (src_tid != in_tid)
		{
			/* We drop these to the floor as we can never reply to the real source which lives on the wrong interface */

			/* When a tunneled packet came in from uplink put the error in the tunnel */
			if (in_tid == SIXXSD_TUNNEL_UPLINK)
			{
				tunnel_log(src_tid, out_tid, SIXXSD_TERR_TUN_FROM_UPLINK, (IPADDRESS *)&ip6->ip6_src);
			}
			else
			{
				tunnel_log(in_tid, out_tid, SIXXSD_TERR_TUN_WRONG_SOURCE_IPV6, (IPADDRESS *)&ip6->ip6_src);
			}
			return;
		}
	}

	/* Ignore link-local destination addresses */
	if (IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_dst))
	{
		tunnel_debug(in_tid, out_tid, packet, len, "iface_route6(%s) - dropping Link-local destined packet\n", is_error ? "error" : "normal");
		return;
	}

	out_tid = address_find((IPADDRESS *)&ip6->ip6_dst, &istunnel);

	/* Is it being send to us? (even on other tunnels etc) */
	if (istunnel && address_islocal((IPADDRESS *)&ip6->ip6_dst))
	{
		struct ip6_ext	*ipe;
		uint8_t		ipe_type;
		uint32_t	plen;

		tunnel_debug(in_tid, out_tid, packet, len, "Local Address\n");

		if (!l3_ipv6_parse(packet, len, &ipe_type, &ipe, &plen)) return;

		/* ICMP packet? */
		tunnel_debug(in_tid, out_tid, packet, len, "Packet Contains %u (ICMPv6 = %u)\n", ipe_type, IPPROTO_ICMPV6);
		if (ipe_type == IPPROTO_ICMPV6)
		{
			struct icmp6_hdr *icmp = (struct icmp6_hdr *)ipe;

			/* We answer ICMP Echo Request */
			switch (icmp->icmp6_type)
			{
			case ICMP6_ECHO_REQUEST:
				iface_send_icmpv6_echo_reply(in_tid, out_tid, packet, len);
				break;

			case ICMP6_ECHO_REPLY:
				/* We only care about these if they came from the remote tunnel endpoint on the tunnel */
				if (istunnel && address_isremote((IPADDRESS *)&ip6->ip6_src) && in_tid == out_tid)
				{
					iface_got_icmpv6_reply(in_tid, packet, len, icmp, plen);
				}
				break;

			case ND_NEIGHBOR_SOLICIT:
				if (ip6->ip6_hlim == 255) iface_send_icmpv6_neigh(in_tid, out_tid, packet, len);
				break;

			default:
				/* Ignore all other ICMP message types */
				break;
			}

			return;
		}

		/* Nothing to see here, please move along */
		iface_send_icmpv6_unreach(in_tid, out_tid, packet, len, ICMP6_DST_UNREACH_NOPORT);
		return;
	}

	/* Don't route out over the same interface as that would just cause a routing loop */
	if (!nosrcchk && out_tid == in_tid)
	{
		/* Trying to send packets to itself, just drop it on the floor */
		tunnel_log(in_tid, out_tid, SIXXSD_TERR_TUN_SAME_IO, (IPADDRESS *)&ip6->ip6_src);
		return;
	}

	/* Prepare the packet for forwarding (MTU and TTL handling */
	if (!iface_prepfwd6(in_tid, out_tid, packet, len, is_error, decrease_ttl)) return;

	/* Send it to the network */
	if (out_tid == SIXXSD_TUNNEL_UPLINK)
	{
		tunnel_debug(in_tid, out_tid, packet, len, "TAPped Packet\n");
		iface_sendtap(in_tid, out_tid, ETH_P_IPV6, packet, len, is_error, packet, len);
		return;
	}

	tunnel_debug(in_tid, out_tid, packet, len, "Tunneled-Packet\n");

	/* <tunnel>::1 is handled above, <tunnel>::2 below, this is thus for the rest in that /64 */
	if (istunnel && !address_isremote((IPADDRESS *)&ip6->ip6_dst))
	{
		iface_send_icmpv6_unreach(in_tid, out_tid, packet, len, ICMP6_DST_UNREACH_NOROUTE);
		return;
	}

	/* <tunnel>::2 and subnets routed behind that */
	tunnel_debug(in_tid, out_tid, packet, len, "Routing to tunnel\n");
	iface_routetun(in_tid, out_tid, IPPROTO_IPV6, packet, len, is_error);
}

VOID iface_route4(const uint16_t in_tid, const uint16_t out_tid_, uint8_t *packet, const uint16_t len, BOOL is_error, BOOL decrease_ttl, BOOL nosrcchk)
{
	struct ip	*ip = (struct ip *)packet;
	uint16_t	out_tid = out_tid_;
	BOOL		istunnel;

	tunnel_debug(in_tid, out_tid, packet, len, "iface_route4(%s)\n", is_error ? "error" : "normal");

	if (!nosrcchk)
	{
		IPADDRESS s;

		ipaddress_make_ipv4(&s, &ip->ip_src);

		/* Do we like the source address coming from this interface? */
		out_tid = address_find(&s, &istunnel);
		if (out_tid != in_tid)
		{
			if (!is_error) iface_send_icmpv4_unreach(in_tid, out_tid, packet, len, ICMP_UNREACH_SRCFAIL);
			else
			{
				char		src[128], dst[128];
				IPADDRESS	d;

				ipaddress_make_ipv4(&d, &ip->ip_dst);

				inet_ntopA((IPADDRESS *)&ip->ip_src, src, sizeof(src));
				inet_ntopA((IPADDRESS *)&ip->ip_dst, dst, sizeof(dst));

				tunnel_debug(in_tid, out_tid, packet, len, "Not sending an unreachable(wrong source) for a error packet: %s -> %s (%u->%u)\n", src, dst, in_tid, out_tid);
			}
			return;
		}
	}

	/* Where does the packet want to go? */
	out_tid = address_find((IPADDRESS *)&ip->ip_dst, &istunnel);

	/* Prepare the packet for forwarding (MTU and TTL handling) */
	if (!iface_prepfwd4(in_tid, out_tid, packet, len, is_error, decrease_ttl)) return;

	/* It goes out over one of our own tunnels */
	if (out_tid != SIXXSD_TUNNEL_UPLINK)
	{
		tunnel_debug(in_tid, out_tid, packet, len, "Routing to tunnel\n");
		iface_routetun(in_tid, out_tid, IPPROTO_IP, packet, len, is_error);
		return;
	}

	/* Send the packet to our tun/tap device and let the kernel handle the routing */
	tunnel_debug(in_tid, out_tid, packet, len, "TAPing Packet\n");
	iface_sendtap(in_tid, out_tid, ETH_P_IP, packet, len, is_error, packet, len);
	return;
}

static VOID iface_send_icmpv6(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, const uint8_t type, const uint8_t code, const uint32_t param, struct in6_addr *dst);
static VOID iface_send_icmpv6(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, const uint8_t type, const uint8_t code, const uint32_t param, struct in6_addr *dst)
{
	struct
	{
		struct ip6_hdr		ip;
		struct icmp6_hdr	icmp;
		uint8_t			payload[2048];
	}				pkt;
	uint32_t			plen;
	uint16_t			t16;
	uint8_t				hlim = 64;

	tunnel_debug(in_tid, out_tid, packet, len, "ICMPv6 %u::%u\n", type, code);

	/* Fill in the payload */
	if (type == ICMP6_ECHO_REPLY)
	{
		struct ip6_ext		*ipe;
		struct icmp6_hdr	*icmp;
		uint8_t			ipe_type;

		tunnel_debug(in_tid, out_tid, packet, len, "ICMPv6 %u::%u - Echo Request\n", type, code);

		if (!l3_ipv6_parse(packet, len, &ipe_type, &ipe, &plen))
		{
			tunnel_debug(in_tid, out_tid, packet, len, "ICMP Echo Request that is broken\n");
			return;
		}

		if (ipe_type != IPPROTO_ICMPV6)
		{
			tunnel_debug(in_tid, out_tid, packet, len, "ICMP Echo Request with unknown extension %04x != ICMP (%04x)\n", ipe_type, IPPROTO_ICMPV6);
			return;
		}

		/* Ping too big? Send an error back instead */
		if (plen > sizeof(pkt.payload))
		{
			tunnel_debug(in_tid, out_tid, packet, len, "ICMP Echo Request that is too big (%u > %u)\n", plen, (unsigned int)sizeof(pkt.payload));
			iface_send_icmpv6_toobig(in_tid, out_tid, packet, len, sizeof(pkt));
			return;
		}

		if (plen < sizeof(*icmp))
		{
			tunnel_debug(in_tid, out_tid, packet, len, "Incomplete ICMP echo request received\n");
			return;
		}

		/* We just want to know the size of the payload */
		plen -= sizeof(*icmp);

		memcpy(pkt.payload, ((uint8_t *)ipe) + sizeof(*icmp), plen);

		/* Steal the parameter out of the ICMPv6 header */
		icmp = (struct icmp6_hdr *)ipe;
		pkt.icmp.icmp6_dataun.icmp6_un_data32[0] = icmp->icmp6_dataun.icmp6_un_data32[0];
	}
	else if (type == ND_NEIGHBOR_ADVERT)
	{
		struct ip6_ext			*ipe;
		uint8_t				ipe_type;
		struct nd_neigh_advert		*adv;
		struct nd_neigh_solicit		*sol;

		tunnel_debug(in_tid, out_tid, packet, len, "ICMPv6 %u::%u - Neighbor Advertisement\n", type, code);

		if (!l3_ipv6_parse(packet, len, &ipe_type, &ipe, &plen))
		{
			tunnel_debug(in_tid, out_tid, packet, len, "ICMP Echo Request that is broken\n");
			return;
		}

		if (ipe_type != IPPROTO_ICMPV6)
		{
			tunnel_debug(in_tid, out_tid, packet, len, "ICMP Echo Request with unknown extension %04x != ICMP (%04x)\n", ipe_type, IPPROTO_ICMPV6);
			return;
		}

		adv = (struct nd_neigh_advert *)&pkt.payload;
		sol = (struct nd_neigh_solicit *)(((uint8_t *)ipe) + sizeof(struct icmp6_hdr));

		hlim = 255;
		plen = sizeof(*adv);

		/* ICMP Neighbour Advertisement */
		pkt.icmp.icmp6_dataun.icmp6_un_data32[0] = ND_NA_FLAG_ROUTER | ND_NA_FLAG_SOLICITED;
		memcpy(&adv->nd_na_target, &sol->nd_ns_target, sizeof(adv->nd_na_target));
	}
	else
	{
		/* How much are we willing to send back of the original packet? */
		plen = 1280 - (sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr));
		tunnel_debug(in_tid, out_tid, packet, len, "ICMPv6 %u::%u - Other - possible plen = %u, len = %u\n", type, code, plen, len);

		plen = len > plen ? plen : len;
		tunnel_debug(in_tid, out_tid, packet, len, "ICMPv6 %u::%u - Other - possible plen = %u\n", type, code, plen);

		memcpy(&pkt.payload, packet, plen);

		pkt.icmp.icmp6_dataun.icmp6_un_data32[0] = htonl(param);
	}

	/* IPv6 */
	pkt.ip.ip6_ctlun.ip6_un1.ip6_un1_flow = htons(0);
	pkt.ip.ip6_ctlun.ip6_un2_vfc = (6 << 4); 
	pkt.ip.ip6_ctlun.ip6_un1.ip6_un1_plen = htons(sizeof(pkt.icmp) + plen);
	pkt.ip.ip6_ctlun.ip6_un1.ip6_un1_hlim = hlim;
	pkt.ip.ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_ICMPV6;

	/* We originate this ICMPv6 packet, either from the incoming or outgoing tunnel IP */
	t16 = htons((in_tid != SIXXSD_TUNNEL_NONE && in_tid != SIXXSD_TUNNEL_UPLINK) ? in_tid : out_tid);

	memcpy(&pkt.ip.ip6_src.s6_addr[0], &g_conf->tunnels.prefix, (48/8));
	memcpy(&pkt.ip.ip6_src.s6_addr[(48/8)],	&t16, sizeof(t16));
	memzero(&pkt.ip.ip6_src.s6_addr[(48/8)+2], (64/8)-1);
	pkt.ip.ip6_src.s6_addr[15] = SIXXSD_TUNNEL_IP_US;

	/* Set the Type & Code */
	pkt.icmp.icmp6_type = type;
	pkt.icmp.icmp6_code = code;

	/* Set the destination */
	if (dst)
	{
		memcpy(&pkt.ip.ip6_dst,	dst, sizeof(pkt.ip.ip6_dst));
		tunnel_debug(in_tid, out_tid, (uint8_t *)&pkt, sizeof(pkt.ip) + sizeof(pkt.icmp) + plen, "ICMPv6 %u::%u - Using provided address\n", type, code);
	}
	else
	{
		struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;

		/* The sender will get this packet back */
		memcpy(&pkt.ip.ip6_dst,	&ip6->ip6_src, sizeof(pkt.ip.ip6_dst));

		tunnel_debug(in_tid, out_tid, (uint8_t *)&pkt, sizeof(pkt.ip) + sizeof(pkt.icmp) + plen, "ICMPv6 %u::%u - Using source address\n", type, code);
	}

	pkt.icmp.icmp6_cksum = htons(0);
	pkt.icmp.icmp6_cksum = ipv6_checksum(&pkt.ip, IPPROTO_ICMPV6, (uint8_t *)&pkt.icmp, sizeof(pkt.icmp) + plen);

	tunnel_debug(in_tid, out_tid, (uint8_t *)&pkt, sizeof(pkt.ip) + sizeof(pkt.icmp) + plen, "ICMPv6 %u::%u - Answer prepared cksum %04x\n", type, code, ntohs(pkt.icmp.icmp6_cksum));

	/* Send it off: it is an error, don't decrease the TTL, don't check the source */
	iface_route6(in_tid, out_tid, (uint8_t *)&pkt, sizeof(pkt.ip) + sizeof(pkt.icmp) + plen, true, false, true);
}

static VOID iface_send_icmpv4(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, const uint8_t type, const uint8_t code, const uint32_t param);
static VOID iface_send_icmpv4(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, const uint8_t type, const uint8_t code, const uint32_t param)
{
	struct ip			*ip = (struct ip *)packet;
	struct
	{
		struct ip		ip;
		struct icmp_hdr		icmp;
		uint8_t			payload[1280 - (sizeof(struct ip) + sizeof(struct icmp_hdr))];
	}				pkt;
	uint16_t			plen;

	tunnel_debug(in_tid, out_tid, packet, len, "ICMPv4 %u::%u\n", type, code);

	if (!tunnel_state_check(in_tid, out_tid, packet, len, true)) return;

	/* How much are we willing to echo back of the original packet? */
	plen = len > sizeof(pkt.payload) ? sizeof(pkt.payload) : len;

	/* IP version 4 */
	pkt.ip.ip_v = 4;
	pkt.ip.ip_hl = sizeof(pkt.ip) / 4;
	pkt.ip.ip_tos = 0;
	pkt.ip.ip_len = htons(sizeof(pkt) - sizeof(pkt.payload) + plen);
	pkt.ip.ip_id = 0x42;
	pkt.ip.ip_off = htons(IP_DF);
	pkt.ip.ip_ttl = 64;
	pkt.ip.ip_p = IPPROTO_ICMP;

	/* Fill in the IP header from the original packet, swapping source & dest */
	memcpy(&pkt.ip.ip_src, &ip->ip_dst, sizeof(pkt.ip.ip_src));
	memcpy(&pkt.ip.ip_dst, &ip->ip_src, sizeof(pkt.ip.ip_dst));

	/* Fill in the payload */
	memcpy(&pkt.payload, packet, plen); /* XXX: hurts */

	/* Set the Type & Code */
	pkt.icmp.icmp_type = type;
	pkt.icmp.icmp_code = code;
	pkt.icmp.icmp_param = htonl(param);
	pkt.icmp.icmp_cksum = htons(0);
	pkt.icmp.icmp_cksum = in_checksum((unsigned char *)&pkt.icmp, sizeof(pkt.icmp) + plen);

	/* Send it off */
	iface_send4(in_tid, out_tid, (const uint8_t *)&pkt, sizeof(pkt) - sizeof(pkt.payload) + plen, NULL, 0, true, NULL, 0);
}

VOID iface_send_icmpv6_echo_reply(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len)
{
	struct sixxsd_tunnel	*outtun = tunnel_grab(out_tid);

	if (!outtun)
	{
		tunnel_debug(in_tid, out_tid, packet, len, "Trying to send echo reply, but outbound interface is not a tunnel!?\n");
		return;
	}

	tunnel_debug(in_tid, out_tid, packet, len, "ICMPv6 Echo Request received, sending Reply\n");

	if (outtun->state == SIXXSD_TSTATE_UP) iface_send_icmpv6(in_tid, out_tid, packet, len, ICMP6_ECHO_REPLY, 0, 0, NULL);
	else iface_unreachtun(in_tid, out_tid, IPPROTO_IPV6, packet, len, false);
}

static VOID iface_send_icmpv6_echo_request(const uint16_t tid, struct in6_addr *dst, const uint8_t *packet, const uint16_t len, const uint16_t seq);
static VOID iface_send_icmpv6_echo_request(const uint16_t tid, struct in6_addr *dst, const uint8_t *packet, const uint16_t len, const uint16_t seq)
{
	/* Packet is a payload, not a real packet (that is, starts with an IPv4 or IPv6 header) */
	tunnel_debug(tid, tid, NULL, 0, "ICMPv6 Echo Request - seqno %u\n", seq);
	iface_send_icmpv6(SIXXSD_TUNNEL_NONE, tid, packet, len, ICMP6_ECHO_REQUEST, 0, (0x4242 << 16) + (seq), dst);
}

VOID iface_send_icmpv6_neigh(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len)
{
	tunnel_debug(in_tid, out_tid, packet, len, "ICMPv6 Neighbor Solicitation\n");
	iface_send_icmpv6(in_tid, out_tid, packet, len, ND_NEIGHBOR_ADVERT, 0, 0, NULL);
}

VOID iface_send_icmpv6_unreach(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, const uint8_t code)
{
	tunnel_debug(in_tid, out_tid, packet, len, "ICMPv6 Unreach %u\n", code);
	iface_send_icmpv6(in_tid, out_tid, packet, len, ICMP6_DST_UNREACH, code, 0, NULL);
}

VOID iface_send_icmpv4_unreach(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, const uint8_t code)
{
	tunnel_debug(in_tid, out_tid, packet, len, "ICMPv4 Unreach %u\n", code);
	iface_send_icmpv4(in_tid, out_tid, packet, len, ICMP_DEST_UNREACH, code, 0);
}

VOID iface_send_icmpv6_ttl(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len)
{
	tunnel_debug(in_tid, out_tid, packet, len, "ICMPv6 TTL\n");
	iface_send_icmpv6(in_tid, out_tid, packet, len, ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT, 0, NULL);
}

VOID iface_send_icmpv4_ttl(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len)
{
	tunnel_debug(in_tid, out_tid, packet, len, "ICMPv4 TTL\n");
	iface_send_icmpv6(in_tid, out_tid, packet, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0, NULL);
}

VOID iface_send_icmpv6_toobig(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, const uint16_t mtu)
{
	tunnel_debug(in_tid, out_tid, packet, len, "ICMPv6 Too Big\n");
	iface_send_icmpv6(in_tid, out_tid, packet, len, ICMP6_PACKET_TOO_BIG, 0, mtu, NULL);
}

VOID iface_send_icmpv4_toobig(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, const uint16_t mtu)
{
	tunnel_debug(in_tid, out_tid, packet, len, "ICMPv4 Too Big\n");
	iface_send_icmpv4(in_tid, out_tid, packet, len, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, mtu);
}

VOID iface_send_icmp_toobig(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, const uint16_t mtu)
{
	struct ip *ip = (struct ip *)packet;
	if (ip->ip_v == 4) iface_send_icmpv4_toobig(in_tid, out_tid, packet, len, mtu);
	else iface_send_icmpv6_toobig(in_tid, out_tid, packet, len, mtu);
}

/* This thread pings all the tunnels that are alive */
static PTR *iface_pinger_thread(PTR UNUSED *arg);
static PTR *iface_pinger_thread(PTR UNUSED *arg)
{
	struct sixxsd_tunnel	*tun;
	uint16_t		tid, t16;
	unsigned int		plen;
	struct in6_addr		dst;
	const char		hi[] = "Thank you for actually looking at the packets, if you need further help don't hesitate to read http://www.sixxs.net/contact/ and peruse the forums!\n";
	const char		rep[] = "You Got Pinged by SixXS!\n";
	struct pingtest		payload;

	/* The destination IPv6 address (minus the tid) */
	memcpy(&dst.s6_addr[0], &g_conf->tunnels.prefix, (48/8));
	memzero(&dst.s6_addr[(48/8)+2], (64/8)-1);
	dst.s6_addr[15] = SIXXSD_TUNNEL_IP_THEM;

	/* Say Hi! to people who look at the packets */
	memcpy(payload.message, hi, sizeof(hi));

	/* Fill up the rest with the repetition string */
	for (plen = strlen(hi); plen <= (sizeof(payload.message) - sizeof(rep)); plen += sizeof(rep))
	{
		memcpy(&payload.message[plen], rep, sizeof(rep));
	}

	/* Do the loopyloop */
	while (g_conf && g_conf->running)
	{
		/* Grab the mutex, to avoid folks from reading results while we ping */
		mutex_lock(g_conf->mutex_pinger);

		for (tid = 0; g_conf && g_conf->running && tid < lengthof(g_conf->tunnels.tunnel); tid++)
		{
			tun = &g_conf->tunnels.tunnel[tid];

			/* Skip all tunnels that are not up */
			if (tun->state != SIXXSD_TSTATE_UP) continue;

			/* Fill in the tid */
			t16 = htons(tid);
			memcpy(&dst.s6_addr[(48/8)], &t16, sizeof(t16));

			/* Update the time, as we are talking microseconds here */
			payload.time_us = gettime_us();

			/* Fill in the magic */
			payload.magic = g_conf->magic[0];

			/* Send the packet */
			iface_send_icmpv6_echo_request(tid, &dst, (uint8_t *)&payload, plen, tun->stats.latency.seq);

			/* Another one out of the door */
			tun->stats.latency.seq++;
			tun->stats.latency.num_sent++;

			/* Shift up the seq_seen bits */
			tun->stats.latency.seq_seen <<= 1;
		}

		/* Unlock the mutex so readers can get results */
		mutex_release(g_conf->mutex_pinger);

		/* Wait another 60 seconds for the next round */
		if (!thread_sleep(60, 0)) break;

		/* We thus ping about every 60 seconds (few milliseconds are used for sending all the pings ;) */
	}

	return NULL;
}

/* This thread reads from the interfaces, passing the packets to the decoder and onward */
static PTR *iface_read_thread(PTR *__sock);
static PTR *iface_read_thread(PTR *__sock)
{
	struct sixxsd_socket	*sock = (struct sixxsd_socket *)__sock;
	uint8_t			buffer[4096];
	struct sockaddr_storage	ss;
	socklen_t		sslen;
	int			len;
	uint16_t		proto, port;
	IPADDRESS		src;

	ipaddress_make_ipv4(&src, NULL);

	/* Do the loopyloop */
	while (g_conf && g_conf->running)
	{
		if (sock->socket == INVALID_SOCKET) break;

		if (sock->type == SIXXSD_SOCK_TUNTAP)
		{
			len = read(sock->socket, buffer, sizeof(buffer));
			if (len < 0)
			{
				mdolog(LOG_ERR, "Could not read from socket %s\n", iface_socket_name(sock->type));
				break;
			}

			proto = (buffer[2] << 8) + buffer[3];

#ifndef _LINUX
			switch (proto)
			{
			case AF_INET:
				proto = ETH_P_IP;
				break;

			case AF_INET6:
				proto = ETH_P_IPV6;
				break;

			default:
				proto = 0;
				break;
			}
#endif

			/* Ignore the tun_pi structure (which is why there is buffer[4] below) */
			len -= 4;

			/* Account this packet */
			tunnel_account_packet_in(SIXXSD_TUNNEL_UPLINK, len);

			/* Send it off: it is not an error, don't decrease the TTL, do check the source */
			switch (proto)
			{
			case ETH_P_IP:
				iface_route4(SIXXSD_TUNNEL_UPLINK, SIXXSD_TUNNEL_NONE, &buffer[4], len, false, false, false);
				break;

			case ETH_P_IPV6:
				iface_route6(SIXXSD_TUNNEL_UPLINK, SIXXSD_TUNNEL_NONE, &buffer[4], len, false, false, false);
				break;

			default:
				assert(false);
				break;
			}

			continue;
		}

		sslen = sizeof(ss);
		len = recvfrom(sock->socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&ss, &sslen);
		if (len < 0)
		{
			mdolog(LOG_ERR, "Couldn't receive properly from socket %s\n", iface_socket_name(sock->type));
			break;
		}

		/* Just in case we mess up the socket setup table */
		assert(sock->af == ss.ss_family);

		/* Pass it through the correct decoder */
		switch (sock->af)
		{
		case AF_INET:
			switch (sock->type)
			{
			case SIXXSD_SOCK_PROTO41:
				ipaddress_set_ipv4(&src, (struct in_addr *)&buffer[offsetof(struct ip, ip_src)]);
				proto41_in(&src, &buffer[20], len - 20);
				break;

			case SIXXSD_SOCK_AYIYA:
				ipaddress_set_ipv4(&src, &((struct sockaddr_in *)&ss)->sin_addr);
				memcpy(&port, ((char *)&ss) + offsetof(struct sockaddr_in, sin_port), sizeof(port));
				port = ntohs(port);
				ayiya_in(&src, AF_INET, sock->proto, port, sock->port, buffer, len);
				break;

			case SIXXSD_SOCK_HB:
				ipaddress_set_ipv4(&src, &((struct sockaddr_in *)&ss)->sin_addr);
				hb_in(&src, buffer, len);
				break;

			default:
				assert(false);
				break;
			}

			break;

		case AF_INET6:
			switch (sock->type)
			{
			case SIXXSD_SOCK_AYIYA:
				memcpy(&port, ((char *)&ss) + offsetof(struct sockaddr_in6, sin6_port), sizeof(port));
				port = ntohs(port);
				ayiya_in(	(IPADDRESS *) &((struct sockaddr_in6 *)&ss)->sin6_addr,
						AF_INET6, sock->proto, port, sock->port, buffer, len);
				break;

			default:
				/* Not supported */
				assert(false);
				break;
			}

			break;

		default:
			assert(false);
			break;
		}
	}

	return NULL;
}

static int iface_init_bindsock(struct sixxsd_context *ctx, SOCKET sock, unsigned int af, unsigned int port);
static int iface_init_bindsock(struct sixxsd_context *ctx, SOCKET sock, unsigned int af, unsigned int port)
{
	struct sockaddr		*sa;
	struct sockaddr_in	localaddr;
	struct sockaddr_in6	localaddr6;
	socklen_t		sa_len, on;
	int			r;

	/* Allow re-use of an address (saving problems when a connection still exists on that socket */
	on = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	on = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
	on = 1;
	setsockopt(sock, SOL_IPV6, IPV6_V6ONLY, &on, sizeof(on));

	/* Give me 8mb of cache ;) */
	on = (8*1024*1024);
	setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &on, sizeof(on));

	if (af == AF_INET)
	{
		sa = (struct sockaddr *)&localaddr;
		sa_len = sizeof(localaddr);
		memzero(&localaddr, sizeof(localaddr));
		localaddr.sin_family = af;
		localaddr.sin_port = htons(port);
	}
	else if (af == AF_INET6)
	{
		sa = (struct sockaddr *)&localaddr6;
		sa_len = sizeof(localaddr6);
		memzero(&localaddr6, sizeof(localaddr6));
		localaddr6.sin6_family = af;
		localaddr6.sin6_port = htons(port);
	}
	else
	{
		ctx_printef(ctx, errno, "Unknown AF %u\n", af);
		return 400;
	}

	r = bind(sock, sa, sa_len);
	if (r < 0)
	{
		ctx_printef(ctx, errno, "Could not bind to socket (%u, %u)\n", af, port);
		return 400;
	}

	return 200;
}

static int iface_init_rawsock(struct sixxsd_context *ctx, SOCKET *sock);
static int iface_init_rawsock(struct sixxsd_context *ctx, SOCKET *sock)
{
#ifdef _LINUX
	socklen_t on;
#endif

	/*
	 * Open an IPv4 RAW socket, so we can use that for sending out IPv4 packets
	 * the kernel then takes care of the MAC addresses and the routing
	 * For some magic reason this can't be done for IPv6...
	 */
#ifdef _LINUX
	*sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
#else
	/* For FreeBSD we only use it for ICMP, proto-41 goes over the other one */
	*sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
#endif
	if (*sock == INVALID_SOCKET)
	{
		ctx_printef(ctx, errno, "Couldn't create RAW socket\n");
		return 400;
	}

	/* Write only */
	shutdown(*sock, SHUT_RD);

#ifdef _LINUX
	/* We supply packets including the IPv4 header */
	on = 1;
	if (setsockopt(*sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		ctx_printef(ctx, errno, "Couldn't set IP_HDRINCL on RAW IPv4 socket\n");
		closesocket(*sock);
		return 400;
	}
#endif

	return 200;
}

static int iface_init_tuntap(struct sixxsd_context *ctx, struct sixxsd_socket *sock);
static int iface_init_tuntap(struct sixxsd_context *ctx, struct sixxsd_socket *sock)
{
	struct ifreq	ifr;
	char		wantname[] = "sixxs";
#ifdef _LINUX
	const char	*tuntapdev = "/dev/net/tun";
#else /* FreeBSD */
	const char	*tuntapdev = "/dev/tun";
	int		reqfd;
	struct stat	stats;

	/* Destroy any existing devices if they are there */
	os_exec("ifconfig %s destroy 2>/dev/null >/dev/null", wantname);
#endif
#ifdef NEED_IFHEAD
	int		mode;
#endif

	sock->socket = open(tuntapdev, O_RDWR);
	if (sock->socket == INVALID_SOCKET)
	{
		ctx_printef(ctx, errno, "Couldn't open device %s\n", tuntapdev);
		return 400;
	}

	memset(&ifr, 0, sizeof(ifr));

#ifdef _LINUX
	/* Request a TUN device */
	ifr.ifr_flags = IFF_TUN;

	/* Set the interface name to sixxs */
	strncpy(ifr.ifr_name, wantname, sizeof(ifr.ifr_name));

	if (ioctl(sock->socket, TUNSETIFF, &ifr) != 0)
#else /* BSD */

	reqfd = socket(AF_INET6, SOCK_DGRAM, 0);
	fstat(sock->socket, &stats);
	devname_r(stats.st_rdev, S_IFCHR, ifr.ifr_name, sizeof(ifr.ifr_name));
	ifr.ifr_data = wantname;

	if (ioctl(reqfd, SIOCSIFNAME, &ifr) != 0)
#endif
	{
		ctx_printef(ctx, errno, "Couldn't set interface name of TUN/TAP device\n");
		closesocket(sock->socket);
		return 400;
	}

#ifdef NEED_IFHEAD
	mode = 1;
	if (ioctl(sock->socket, TUNSIFHEAD, &mode, sizeof(mode)) == -1)
	{
		ctx_printef(ctx, errno, "Couldn't set interface TUNSIFHEAD to enabled: %s (%d)\n",
				strerror(errno), errno);
		closesocket(sock->socket);
		return 400;
	}
#endif

	return 200;
}

static int iface_init_proto41(struct sixxsd_context *ctx, struct sixxsd_socket *sock, unsigned int af);
static int iface_init_proto41(struct sixxsd_context *ctx, struct sixxsd_socket *sock, unsigned int af)
{
	socklen_t	on;

	sock->socket = socket(af, SOCK_RAW, IPPROTO_IPV6);
	if (sock->socket == INVALID_SOCKET)
	{
		ctx_printef(ctx, errno, "Could not create Proto-41 socket (%u)\n", af);
		return 400;
	}

	on = (8*1024*1024);
	setsockopt(sock->socket, SOL_SOCKET, SO_RCVBUF, &on, sizeof(on));

	return 200;
}

static int iface_init_udp(struct sixxsd_context *ctx, struct sixxsd_socket *sock, unsigned int af, unsigned int proto, unsigned int port);
static int iface_init_udp(struct sixxsd_context *ctx, struct sixxsd_socket *sock, unsigned int af, unsigned int proto, unsigned int port)
{
	int ret;

	sock->socket = socket(af, proto, 0);
	if (sock->socket == INVALID_SOCKET)
	{
		ctx_printef(ctx, errno, "Could not create UDP socket\n");
		return 400;
	}

	/* Bind to the right socket */
	ret = iface_init_bindsock(ctx, sock->socket, af, port);
	if (ret != 200)
	{
		closesocket(sock->socket);
		return ret;
	}

	return 200;
}

VOID iface_upnets(VOID)
{
	unsigned int		i;
	struct sixxsd_tunnels	*tuns;
	struct sixxsd_subnets	*subs;

	/* Not up yet */
	if (g_conf->tuntap == INVALID_SOCKET) return;

	tuns = &g_conf->tunnels;
	if (!ipaddress_is_unspecified(&tuns->prefix) && !tuns->online)
	{
#ifdef _LINUX
		os_exec("/sbin/ip -6 ro add %s:/48 dev sixxs", tuns->prefix_asc);
#else /* FREEBSD */
		os_exec("/sbin/route add -inet6 %s:/48 -interface sixxs", tuns->prefix_asc);
#endif
		tuns->online = true;
	}

	for (i = 0; i <= g_conf->subnets_hi; i++)
	{
		subs = &g_conf->subnets[i];
		if (subs->online)
		{
			mdolog(LOG_INFO, "Subnet %u is already online\n", i);
		}

#ifdef _LINUX
		os_exec("/sbin/ip -6 ro add %s%s::/%u dev sixxs",
#else /* FREEBSD */
		os_exec("/sbin/route add -inet6 %s%s::/%u -interface sixxs",
#endif
			subs->prefix_asc,
			subs->prefix_length == 40 ? "00" : "",
			subs->prefix_length);

		subs->online = true;
	}
}

int iface_exit(struct sixxsd_context *ctx)
{
	unsigned int i;

	ctx_printf(ctx, "Shutting down sockets\n");

	/* Close our RAW IPv4 socket */
	if (g_conf->rawsocket_ipv4 != INVALID_SOCKET)
	{
		closesocket(g_conf->rawsocket_ipv4);
		g_conf->rawsocket_ipv4 = INVALID_SOCKET;
	}

	for (i = 0; i < lengthof(g_conf->sockets); i++)
	{
		if (g_conf->sockets[i].socket == INVALID_SOCKET) continue;
		closesocket(g_conf->sockets[i].socket);
	}

	return 200;
}

int iface_init(struct sixxsd_context *ctx)
{
	struct sixxsd_socket	*s;
	unsigned int		i;
	int			ret;
	char			buf[256];

	struct
	{
		unsigned int	type,	af,		proto,		 port;
	} types[] =
	{
		{ SIXXSD_SOCK_TUNTAP,	0,		0,		0		},
		{ SIXXSD_SOCK_PROTO41,	AF_INET,	0,		0		},
		{ SIXXSD_SOCK_AYIYA,	AF_INET,	SOCK_DGRAM,	AYIYA_PORT	},
		{ SIXXSD_SOCK_AYIYA,	AF_INET6,	SOCK_DGRAM,	AYIYA_PORT	},
		{ SIXXSD_SOCK_HB,	AF_INET,	SOCK_DGRAM,	HEARTBEAT_PORT	},
	};

	/* Should not be initialized yet */
	assert(g_conf->tuntap == INVALID_SOCKET);

	ret = iface_init_rawsock(ctx, &g_conf->rawsocket_ipv4);
	if (ret != 200) return ret;

	for (i = 0; i < lengthof(types); i++)
	{
		s = &g_conf->sockets[i];

		switch (types[i].type)
		{
		case SIXXSD_SOCK_TUNTAP:
			ret = iface_init_tuntap(ctx, s);
			if (ret != 200) return ret;
			g_conf->tuntap = s->socket;
			break;

		case SIXXSD_SOCK_PROTO41:
			ret = iface_init_proto41(ctx, s, types[i].af);
			if (ret != 200) return ret;
#ifdef _FREEBSD
			g_conf->rawsocket_proto41 = s->socket;
#endif
			break;

		case SIXXSD_SOCK_AYIYA:
		case SIXXSD_SOCK_HB:
			ret = iface_init_udp(ctx, s, types[i].af, types[i].proto, types[i].port);
			if (ret != 200) return ret;
			break;

		default:
			assert(false);
			break;
		}

		ctx_printf(ctx, "Opened socket %u :: %s\n", i, iface_socket_name(types[i].type));

		sock_setblock(s->socket);

		s->type		= types[i].type;
		s->af		= types[i].af;
		s->proto	= types[i].proto;
		s->port		= types[i].port;
	}

	if (g_conf->tuntap == INVALID_SOCKET)
	{
		ctx_printf(ctx, "No valid tun/tap\n");
		return 400;
	}

	/* Start thread */
	ctx_printf(ctx, "Starting Interface threads\n");
	for (i = 0; i < lengthof(types); i++)
	{
		snprintf(buf, sizeof(buf), "Reader %s", iface_socket_name(types[i].type));
		if (!thread_add(ctx, buf, iface_read_thread, (PTR *)&g_conf->sockets[i], NULL, true)) return 400;
		ctx_printf(ctx, "Threading socket %u :: %s\n", i, iface_socket_name(types[i].type));
	}

	/* Start a thread which pings alive endpoints */
	if (!thread_add(ctx, buf, iface_pinger_thread, NULL, NULL, true)) return 400;

	/* Set sysconf stuff making sure this is set ;) */
#ifdef _LINUX
	os_exec("sysctl -q -w net.ipv6.conf.default.forwarding=1");
	os_exec("sysctl -q -w net.ipv6.conf.all.forwarding=1");

	/* Make sure that 'sit' and 'tunnel4' are both gone as we'll handle proto-41 thank you very much */
	/* If one does not remove tunnel4 (which is the actual thing linking into the protocol list) */
	/* The kernel helpfully will keep on replying with ICMP unreachables... */
	os_exec("rmmod sit 2>/dev/null");
	os_exec("rmmod tunnel4 2>/dev/null");

	/* Enable our interface */
	os_exec("/sbin/ip link set up dev sixxs");

#else /* FreeBSD */
	os_exec("sysctl -w net.inet6.ip6.forwarding=1");

	/* Remove proto-41 driver */

	/* Enable our interface */
	os_exec("ifconfig sixxs up");
#endif

	/* Bring up our networks */
	iface_upnets();

	return 200;
}

uint16_t address_find(IPADDRESS *addr, BOOL *istunnel)
{
	struct sixxsd_subnet	*s;
	uint16_t		tid;

	/* Try to get it from the tunnel ranges */
	tid = tunnel_get(addr, istunnel);
	if (tid != SIXXSD_TUNNEL_NONE)
	{
		return tid;
	}

	/* Subnet then? */
	s = subnet_get(addr);
	if (s)
	{
		*istunnel = false;
		return s->tunnel_id;
	}

	/* Not ours thus must be on the uplink */
	return SIXXSD_TUNNEL_UPLINK;
}

BOOL address_islocal(IPADDRESS *addr)
{
	return (addr->a32[2] == htonl(0) && addr->a32[3] == htonl(SIXXSD_TUNNEL_IP_US)) ? true : false;
}

BOOL address_isremote(IPADDRESS *addr)
{
	return (addr->a32[2] == htonl(0) && addr->a32[3] == htonl(SIXXSD_TUNNEL_IP_THEM)) ? true : false;
}

