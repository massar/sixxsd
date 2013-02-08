/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2012 All Rights Reserved
************************************************************
 Incoming ICMPv4 packets

 We try to deduce if they signify an error for a tunnel
 That way, the user can see through the live status that
 their endpoint is generating errors and what node is
 generating them.

 Might not be fool-proof as it can be spoofed easily.
***********************************************************/
#include "sixxsd.h"

const char module_icmpv4[] = "icmpv4";
#define module module_icmpv4

/*
 * Typically we receive:
 *
 * IP <rtr> -> <us>
 * ICMPv4 <unreach (admin|host|net)>
 * first <n> bytes of packet we sent:
 *   src = <us>
 *   dst = <them>
 *   proto = <41 | udp>
 *
 * Note that we can only count errors, nothing else
 *
 */
VOID icmpv4_in(const IPADDRESS *org, uint8_t *packet, const uint32_t len)
{
	struct icmp_hdr			*icmp = (struct icmp_hdr *)packet;
	struct ip			*ip;
	uint16_t			tid;
	IPADDRESS			src;
	enum sixxsd_tunnel_errors	err;

	switch (icmp->icmp_type)
	{
	case ICMP_ECHOREPLY:
	case ICMP_SOURCE_QUENCH:
	case ICMP_REDIRECT:
	case ICMP_TIMESTAMP:
	case ICMP_TIMESTAMPREPLY:
	case ICMP_INFO_REQUEST:
	case ICMP_INFO_REPLY:
	case ICMP_ADDRESS:
	case ICMP_ADDRESSREPLY:
		/* Ignore non-error ICMP types */
		return;

	case ICMP_ECHO:
		/* We count the number of ICMPv4 pings people sent */
		err = SIXXSD_TERR_ICMPV4_ECHO_REQUEST;
		break;

	case ICMP_DEST_UNREACH:
	case ICMP_TIME_EXCEEDED:
	case ICMP_PARAMETERPROB:
	default:
		/*
		 * Consider the rest errors
		 * especially as we do not know them
		 */
		err = SIXXSD_TERR_ICMPV4_ERROR;
		break;
	}

	/* The IPv4 packet following it */
	ip = (struct ip *)(packet + sizeof(*icmp));

	/* Check if it is us - should be, otherwise why do we get it? */
	if (memcmp(ipaddress_ipv4(&g_conf->pop_ipv4), &ip->ip_src, sizeof(ip->ip_src)) != 0)
	{
		/* Ignore it, not us anyway */
		return;
	}

	/* The destination of our packet is the endpoint we are looking for */
	ipaddress_make_ipv4(&src, &ip->ip_dst);

	/* Find the IPv4 address in our tunnel table */
	tid = tunnel_find(&src);

	/* Not an endpoint known to us */
	if (tid == SIXXSD_TUNNEL_NONE)
	{
		/* Ignore it */
		return;
	}

	/* Note the problem */
	tunnel_log(SIXXSD_TUNNEL_NONE, tid, packet, len, err, org);
}

