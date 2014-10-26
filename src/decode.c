/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2013 All Rights Reserved
************************************************************
 Packet decoder
***********************************************************/

#include "sixxsd.h"

const char module_decode[] = "decode";
#define module module_decode

BOOL l3_ipv6_parse(const uint16_t in_tid, const uint16_t out_tid,
		   const uint8_t *packet, const uint32_t len,
		   uint8_t *_payload_type, uint8_t **_payload, uint32_t *_plen)
{
	struct ip6_hdr		*ip = (struct ip6_hdr *)packet;
	struct ip6_ext		*ipe;
	uint8_t			ipe_type, jumbogram = 0;
	uint32_t		plen, hlen = 0, l;
	struct ip6_rthdr	*rt;
	struct ip6_opt		*opt;

	if (len < sizeof(*ip))
	{
		tunnel_debug(in_tid, out_tid, packet, len,
				"IPv6: Short IPv6 packet received of len %u\n",
				len);
		return false;
	}

	if ((ip->ip6_ctlun.ip6_un2_vfc >> 4) != 6)
	{
		tunnel_debug(in_tid, out_tid, packet, len,
				"IPv6: Corrupt IP version %u packet found\n",
				(ip->ip6_ctlun.ip6_un2_vfc>>4));
		return false;
	}

	/* Drop packets with a 0 TTL as they should have never been forwarded */
	if (ip->ip6_ctlun.ip6_un1.ip6_un1_hlim == 0)
	{
		tunnel_debug(in_tid, out_tid, packet, len,
				"HopLimit == 0 -> dropping it\n");
		return false;
	}

	/* Save the type of the next header */
	ipe_type = ip->ip6_nxt;
	/* Step to the next header */
	ipe = (struct ip6_ext *)(((char *)ip) + sizeof(*ip));
	plen = ntohs(ip->ip6_plen);

	/*
	 * plen can be 0 when it is a Jumbogram Payload Hop-By-Hop option
	 * Hence make sure we get one if that is the case
	 */
	if (plen == 0)
	{
		/* Require a Jumbogram option */
		jumbogram = 1;
	}
	else if ((plen + sizeof(*ip)) > len)
	{
		/* Indicated Payload Length + header is larger than what we got */
		mdolog(LOG_WARNING, "Payload Length larger than packet data\n");

		/* Send ICMPv6 Parameter Problem - Header */
		iface_send_icmpv6_unreach(in_tid, out_tid, packet, len, ICMP6_PARAMPROB_HEADER);
		return false;
	}

	/*
	 * Skip the hopbyhop options that we know.
	 * The problem is that for unknown
	 * hopbyhop options we don't know
	 * if there is a ipe->ip6e_nxt field
	 * in the following header, hence we then bail out
	 *
	 * See https://www.sixxs.net/faq/sixxs/?faq=sixxsd
	 */
	while (	ipe_type == IPPROTO_HOPOPTS ||
		ipe_type == IPPROTO_ROUTING ||
		ipe_type == IPPROTO_AH ||
		ipe_type == IPPROTO_DSTOPTS ||
		ipe_type == IPPROTO_MH ||
		ipe_type == IPPROTO_HIP ||
		ipe_type == IPPROTO_SHIM6)
	{
		/* Save the type of the next header */
		ipe_type = ipe->ip6e_nxt;

		/* Step to the next header */
		l = ((ipe->ip6e_len * 8) + 8);

		/* How much header we saw already */
		hlen += l;

		ipe  = (struct ip6_ext *)(((char *)ipe) + l);

		/* Check for corrupt packets */
		if ((char *)ipe > ((char *)(ip) + len))
		{
			mdolog(LOG_WARNING, "CORRUPT: Header chain beyond packet data\n");
			/* Send ICMPv6 Parameter Problem - Header */
			iface_send_icmpv6_unreach(in_tid, out_tid, packet, len, ICMP6_PARAMPROB_HEADER);
			return false;
		}

		switch (ipe_type)
		{
		case IPPROTO_HOPOPTS:
			opt = (struct ip6_opt *)ipe;
			if (opt->ip6o_type == IP6OPT_JUMBO)
			{
				struct ip6_opt_jumbo *jmb;

				/* Found the Jumbo header */
				if (jumbogram == 0)
				{
					mdolog(LOG_WARNING, "Found Jumbo Option but Payload Length was already set to %u\n", plen);
					iface_send_icmpv6_unreach(in_tid, out_tid, packet, len, ICMP6_PARAMPROB_HEADER);
					return false;
				}
				else if (jumbogram > 1)
				{
					/* Multiple Jumbo Options, awesome */
					mdolog(LOG_WARNING, "Found multiple Jumbo Options\n");
					iface_send_icmpv6_unreach(in_tid, out_tid, packet, len, ICMP6_PARAMPROB_HEADER);
					return false;
				}

				/* Found another Jumbo Option */
				jumbogram++;

				/* The Jumbo Option */
				jmb = (struct ip6_opt_jumbo *)ipe;

				/* The payload length */
				plen =	(jmb->ip6oj_jumbo_len[0] << 24) +
					(jmb->ip6oj_jumbo_len[1] << 16) +
					(jmb->ip6oj_jumbo_len[2] <<  8) +
					(jmb->ip6oj_jumbo_len[3]);

				/* RFC2675 Section 2 "Must be greater than 65535" */
				if (plen <= 65535 || (plen + sizeof(*ip)) > len)
				{
					/* Indicated Payload Length + header is larger than what we got */
					if (plen <= 65535)
					{
						mdolog(LOG_WARNING, "Jumbo Payload smaller than minimum (%u vs 65535)\n", plen);
					}
					else
					{
						mdolog(LOG_WARNING, "Jumbo Payload larger than packet data (%" PRIu64 " vs %u)\n", (plen + (uint64_t)sizeof(*ip)), len);
					}

					iface_send_icmpv6_unreach(in_tid, out_tid, packet, len, ICMP6_PARAMPROB_HEADER);
					return false;
				}
			}
			break;

		case IPPROTO_ROUTING:
			rt = (struct ip6_rthdr *)ipe;
			if (rt->ip6r_type == 0)
			{
				tunnel_debug(in_tid, out_tid, packet, len,
					"IPv6: RH0 packet encountered\n");
				iface_send_icmpv6_unreach(in_tid, out_tid, packet, len, ICMP6_DST_UNREACH_ADMIN);
				return false;
			}
			break;

		default:
			break;
		}

	}

	if (jumbogram != 0)
	{
		mdolog(LOG_WARNING, "Payload Length was 0 without Jumbo Option\n");
		iface_send_icmpv6_unreach(in_tid, out_tid, packet, len, ICMP6_PARAMPROB_HEADER);
		return false;
	}

	/* Substract the length of headers we saw */
	if (hlen >= plen)
	{
		plen -= hlen;
	}

	/* All okay */
	if (_payload_type)	*_payload_type = ipe_type;
	if (_payload)		*_payload = (uint8_t *)ipe;
	if (_plen)		*_plen = plen;

	return true;
}

BOOL l3_ipv4_parse(const uint16_t in_tid, const uint16_t out_tid,
		   const uint8_t *packet, const uint32_t len,
		   uint8_t *_payload_type, uint8_t **_payload, uint32_t *_plen)
{
	struct ip	*ip = (struct ip *)packet;
	uint32_t	hlen;

	if (len < sizeof(*ip))
	{
		tunnel_debug(in_tid, out_tid, packet, len,
				"IPv4: Short IPv4 packet received of len %u\n",
				len);
		return false;
	}

	hlen = ip->ip_hl * 4;
	if (hlen < sizeof(*ip))
	{
		tunnel_debug(in_tid, out_tid, packet, len,
				"IPv4: Header length smaller than IPv4 packet (%u)\n",
				hlen);
		return false;
	}

	if (hlen >= len)
	{
		tunnel_debug(in_tid, out_tid, packet, len,
				"IPv4: Header length bigger equal received length (%u >= %u)\n",
				hlen, len);
		return false;
	}

	/* All okay */
	if (_payload_type)	*_payload_type = ip->ip_p;
	if (_payload)		*_payload = (uint8_t *)&packet[hlen];
	if (_plen)		*_plen = len - hlen;

	return true;
}

