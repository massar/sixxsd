/******************************************************
 SixXSd - SixXS PoP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2011 All Rights Reserved
*******************************************************
 $Author: jeroen $
 $Id: $
 $Date: $

 SixXSd AYIYA (Anything in Anything) code
*******************************************************/

#include "sixxsd.h"

const char module_ayiya[] = "ayiya";
#define module module_ayiya

struct pseudo_ayh
{
	struct ayiyahdr	ayh;
	IPADDRESS	identity;
	sha1_byte	hash[SHA1_DIGEST_LENGTH];
	uint8_t		payload[2048];
} PACKED;

/*
 * AYIYA Log Rate limiting
 * Remember the last 10 hosts, this could cause messages
 * to be dropped but that is better as a log flood
 * This applies only to Warning & Error messages
 */

/*
struct sockaddr_storage lastlogs[10];
int log_last = 0;
*/
static VOID ayiya_log(int level, const IPADDRESS *src, uint8_t protocol, uint16_t sport, uint16_t dport, const IPADDRESS *identity, const char *ATTR_RESTRICT fmt, ...) ATTR_FORMAT(printf, 7, 8);
static VOID ayiya_log(int level, const IPADDRESS *src, uint8_t protocol, uint16_t sport, uint16_t dport, const IPADDRESS *identity, const char *fmt, ...)
{
	char		buf[1024];
	char		srca[NI_MAXHOST], id[NI_MAXHOST];
	va_list		ap;

	/* First check for ratelimiting */
	if (level == LOG_ERR || level == LOG_WARNING)
	{

	}

	/* Humans like to read text */
	inet_ntopA(src, srca, sizeof(srca));
	inet_ntopA(identity, id, sizeof(id));

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	
	/* Print the host+port this is coming from */
	mdolog(level, "[%s]:%u/%u->%u(%s): %s", srca, protocol, sport, dport, id, buf);

#if 0
	/* Add this one */
	memcpy(&lastlogs[log_last], &clientaddr, sizeof(lastlogs[log_last]));

	/* Cycle(tm) */
	log_last++;
	log_last%=(sizeof(lastlogs)/sizeof(struct in_addr));
#endif
}

VOID ayiya_out_pseudo(struct sixxsd_tunnel *tun, struct pseudo_ayh *s, const uint16_t out_tid, const uint8_t protocol, const uint8_t *packet, const uint16_t len);
VOID ayiya_out_pseudo(struct sixxsd_tunnel *tun, struct pseudo_ayh *s, const uint16_t out_tid, const uint8_t protocol, const uint8_t *packet, const uint16_t len)
{
	SHA_CTX		sha1;
	sha1_byte	hash[SHA1_DIGEST_LENGTH], shatmp[sizeof(*s)];

	/* Standard AYIYA values */
	s->ayh.ayh_idlen = 4;			/* 2^4 = 16 bytes = 128 bits (IPv6 address) */
	s->ayh.ayh_idtype = ayiya_id_integer;
	s->ayh.ayh_siglen = 5;			/* 5*4 = 20 bytes = 160 bits (SHA1) */
	s->ayh.ayh_hshmeth = ayiya_hash_sha1;
	s->ayh.ayh_autmeth = ayiya_auth_sharedsecret;
	s->ayh.ayh_opcode = ayiya_op_forward;
	s->ayh.ayh_nextheader = protocol;

	s->ayh.ayh_epochtime = htonl(gettime());

	/* Our side of the tunnel */
	memcpy(&s->identity, &g_conf->tunnels.prefix, (48/8));
	s->identity.a16[(48/16)] = htons(out_tid);
	memzero(&s->identity.a8[64/8], (56/8));
	s->identity.a8[(128/8)-1] = 1;

	/* The payload */
	memcpy(s->payload, packet, len);

	/*
	 * The hash of the shared secret needs to be in the
	 * spot where we later put the complete hash
	 */
	memcpy(&s->hash, &tun->ayiya_sha1, sizeof(s->hash));

	/* Generate a SHA1 */
	SHA1_Init(&sha1);
	/* Hash the complete AYIYA packet */
	SHA1_Update(&sha1, (unsigned char *)s, sizeof(*s) - sizeof(s->payload) + len, shatmp);

	/* XXX: can we 'incrementally update' a SHA1 hash, as in sha1(header) + sha1(payload) ? */
	/* Store the hash in the packets hash */
	SHA1_Final(hash, &sha1);

	/* Store the hash in the packet */
	memcpy(&s->hash, &hash, sizeof(s->hash));
}

VOID ayiya_out_ipv4(struct sixxsd_tunnel *tun, const uint16_t in_tid, const uint16_t out_tid, const uint8_t protocol, const uint8_t *packet, const uint16_t len, BOOL is_error);
VOID ayiya_out_ipv4(struct sixxsd_tunnel *tun, const uint16_t in_tid, const uint16_t out_tid, const uint8_t protocol, const uint8_t *packet, const uint16_t len, BOOL is_error)
{
	struct
	{
		struct ip		ip;
		struct udphdr		udp;
		struct pseudo_ayh	s;
	} PACKED			pkt;

	/* IPv4 */
	pkt.ip.ip_v = 4;
	pkt.ip.ip_hl = sizeof(pkt.ip)/4;
	pkt.ip.ip_tos = 0;
	pkt.ip.ip_len = htons(sizeof(pkt) - sizeof(pkt.s.payload) + len);
	pkt.ip.ip_id = 0x42;
	pkt.ip.ip_off = htons(IP_DF);
	pkt.ip.ip_ttl = 64;
	pkt.ip.ip_p = IPPROTO_UDP;
	memcpy(&pkt.ip.ip_src, ipaddress_ipv4(&g_conf->pop_ipv4),	sizeof(pkt.ip.ip_src));
	memcpy(&pkt.ip.ip_dst, ipaddress_ipv4(&tun->ip_them),		sizeof(pkt.ip.ip_dst));

	/* UDP */
	pkt.udp.uh_sport = htons(tun->ayiya_port_us);
	pkt.udp.uh_dport = htons(tun->ayiya_port_them);
	pkt.udp.uh_ulen = htons(sizeof(pkt.udp) + sizeof(pkt.s) - sizeof(pkt.s.payload) + len);

	/* Fill in the pseudo header */
	ayiya_out_pseudo(tun, &pkt.s, out_tid, protocol, packet, len);
	
	/* We don't do checksums, they are optional for UDP anyway and there is already a hash in AYIYA anyway */
	pkt.udp.uh_sum = htons(0);

	/* Send the packet outbound */
	iface_send4(in_tid, out_tid, (uint8_t *)&pkt, sizeof(pkt) - sizeof(pkt.s.payload) + len, NULL, 0, is_error, packet, len);
}

VOID ayiya_out_ipv6(struct sixxsd_tunnel *tun, const uint16_t in_tid, const uint16_t out_tid, const uint8_t protocol, const uint8_t *packet, const uint16_t len, BOOL is_error);
VOID ayiya_out_ipv6(struct sixxsd_tunnel *tun, const uint16_t in_tid, const uint16_t out_tid, const uint8_t protocol, const uint8_t *packet, const uint16_t len, BOOL is_error)
{
	struct
	{
		struct ip6_hdr		ip;
		struct udphdr		udp;
		struct pseudo_ayh	s;
	} PACKED			pkt;

        /* IPv6 */
        pkt.ip.ip6_ctlun.ip6_un1.ip6_un1_flow = htons(0);
        pkt.ip.ip6_ctlun.ip6_un2_vfc = (6 << 4);
        pkt.ip.ip6_ctlun.ip6_un1.ip6_un1_plen = htons(sizeof(pkt.udp) + sizeof(pkt.s) - sizeof(pkt.s.payload) + len);
        pkt.ip.ip6_ctlun.ip6_un1.ip6_un1_hlim = 64;
        pkt.ip.ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_UDP;

	memcpy(&pkt.ip.ip6_src, &g_conf->pop_ipv6,	sizeof(pkt.ip.ip6_src));
	memcpy(&pkt.ip.ip6_dst, &tun->ip_them,		sizeof(pkt.ip.ip6_dst));

	/* UDP */
	pkt.udp.uh_sport = htons(tun->ayiya_port_us);
	pkt.udp.uh_dport = htons(tun->ayiya_port_them);
	pkt.udp.uh_ulen = htons(sizeof(pkt.udp) + sizeof(pkt.s) - sizeof(pkt.s.payload) + len);

	/* Fill in the pseudo header */
	ayiya_out_pseudo(tun, &pkt.s, out_tid, protocol, packet, len);

	/* In IPv6 a UDP checksum is mandatory */	
	pkt.udp.uh_sum = htons(0);
	pkt.udp.uh_sum = ipv6_checksum(&pkt.ip, IPPROTO_UDP, (uint8_t *)&pkt.udp, sizeof(pkt.udp) + sizeof(pkt.s) - sizeof(pkt.s.payload) + len);

	/* Send it off: maybe an error, don't decrease the TTL, don't check the source */
	iface_route6(in_tid, out_tid, (uint8_t *)&pkt, sizeof(pkt) - sizeof(pkt.s.payload) + len, is_error, false, true);
}

/* From the interface (kernel) -> the other side of the tunnel */
VOID ayiya_out(const uint16_t in_tid, const uint16_t out_tid, const uint8_t protocol, const uint8_t *packet, const uint16_t len, BOOL is_error)
{
	struct sixxsd_tunnel *tun;

	tun = tunnel_grab(out_tid);
	if (!tun)
	{
		if (!is_error) iface_send_icmpv6_unreach(in_tid, out_tid, packet, len, ICMP6_DST_UNREACH_ADMIN);
		return;
	}

	if (len > sizeof(((struct pseudo_ayh *)NULL)->payload) || len > tun->mtu)
	{
		if (!is_error) iface_send_icmp_toobig(in_tid, out_tid, packet, len, tun->mtu);
		return;
	}

	if (!tunnel_state_check(in_tid, out_tid, packet, len, is_error)) return;

	if (ipaddress_is_ipv4(&tun->ip_them))
	{
		ayiya_out_ipv4(tun, in_tid, out_tid, protocol, packet, len, is_error);
	}
	else
	{
		ayiya_out_ipv6(tun, in_tid, out_tid, protocol, packet, len, is_error);
	}
}

/*
 * From the other side of the tunnel -> interface (kernel)
 * src        = where the packet came from
 * protocol   = the protocol in which AYIYA was carried
 * sport      = source port
 * dport      = destination port
 * packet     = buffer containing the packet
 * length     = length of the packet
*/
VOID ayiya_in(const IPADDRESS *src, const uint8_t af, const uint8_t protocol, const uint16_t sport, const uint16_t dport, const uint8_t *packet, const uint32_t len)
{
	SHA_CTX			sha1;
	struct pseudo_ayh	*s = (struct pseudo_ayh *)packet;
	sha1_byte		their_hash[SHA1_DIGEST_LENGTH],
				our_hash[SHA1_DIGEST_LENGTH],
				shatmp[sizeof(*s)];
	int64_t			i;
	struct sixxsd_tunnel	*tun;
	uint16_t		in_tid;
	uint32_t		plen;
	BOOL			is_tunnel;
	uint64_t		currtime;

	/*
	 * - idlen must be 4 (2^4 = 16 bytes = 128 bits = IPv6 address)
	 * - It must be an integer identity
	 * - siglen must be 5 (5*4 = 20 bytes = 160 bits = SHA1)
	 * - Hash Method == SHA1
	 * - Authentication Method must be Shared Secret
	 * - Next header must be IPv6 or IPv6 No Next Header
	 * - Opcode must be 0 - 2
	 */
        if (	s->ayh.ayh_idlen != 4 ||
		s->ayh.ayh_idtype != ayiya_id_integer ||
		s->ayh.ayh_siglen != 5 ||
		s->ayh.ayh_hshmeth != ayiya_hash_sha1 ||
		s->ayh.ayh_autmeth != ayiya_auth_sharedsecret ||
		(s->ayh.ayh_nextheader != IPPROTO_IPV4 &&
		 s->ayh.ayh_nextheader != IPPROTO_IPV6 &&
		 s->ayh.ayh_nextheader != IPPROTO_NONE) ||
		(s->ayh.ayh_opcode != ayiya_op_noop &&
		 s->ayh.ayh_opcode != ayiya_op_forward &&
		 s->ayh.ayh_opcode != ayiya_op_echo_request &&
		 s->ayh.ayh_opcode != ayiya_op_echo_request_forward))
	{
		/* Invalid AYIYA packet */
		ayiya_log(LOG_ERR, src, protocol, sport, dport, &s->identity, "incoming: Dropping invalid AYIYA packet\n");
		ayiya_log(LOG_ERR, src, protocol, sport, dport, &s->identity, "idlen:   %u != %u\n", s->ayh.ayh_idlen, 4);
		ayiya_log(LOG_ERR, src, protocol, sport, dport, &s->identity, "idtype:  %u != %u\n", s->ayh.ayh_idtype, ayiya_id_integer);
		ayiya_log(LOG_ERR, src, protocol, sport, dport, &s->identity, "siglen:  %u != %u\n", s->ayh.ayh_siglen, 5);
		ayiya_log(LOG_ERR, src, protocol, sport, dport, &s->identity, "hshmeth: %u != %u\n", s->ayh.ayh_hshmeth, ayiya_hash_sha1);
		ayiya_log(LOG_ERR, src, protocol, sport, dport, &s->identity, "autmeth: %u != %u\n", s->ayh.ayh_autmeth, ayiya_auth_sharedsecret);
		ayiya_log(LOG_ERR, src, protocol, sport, dport, &s->identity, "nexth  : %u != %u || %u\n", s->ayh.ayh_nextheader, IPPROTO_IPV6, IPPROTO_NONE);
		ayiya_log(LOG_ERR, src, protocol, sport, dport, &s->identity, "opcode : %u != %u || %u || %u || %u\n", s->ayh.ayh_opcode, ayiya_op_noop, ayiya_op_forward, ayiya_op_echo_request, ayiya_op_echo_request_forward);
		return;
	}

	in_tid = tunnel_get(&s->identity, &is_tunnel);
	if (in_tid == SIXXSD_TUNNEL_NONE)
	{
		ayiya_log(LOG_WARNING, src, protocol, sport, dport, &s->identity, "incoming: Unknown endpoint\n");
		return;
	}

	tun = tunnel_grab(in_tid);
	if (!tun || tun->state == SIXXSD_TSTATE_DISABLED)
	{
		tunnel_log(SIXXSD_TUNNEL_NONE, in_tid, SIXXSD_TERR_TUN_DISABLED, src);
		return;
	}

	if (tun->type != SIXXSD_TTYPE_AYIYA)
	{
		tunnel_log(SIXXSD_TUNNEL_NONE, in_tid, SIXXSD_TERR_AYIYA_FOR_NON_AYIYA, src);
		return;
	}

	if (s->ayh.ayh_nextheader == IPPROTO_IPV6 && ((s->payload[0] >> 4) != 0x6))
	{
		tunnel_log(SIXXSD_TUNNEL_NONE, in_tid, SIXXSD_TERR_TUN_PAYLOAD_NOT_IPV6, src);
		return;
	}

	if (s->ayh.ayh_nextheader == IPPROTO_IPV4 && ((s->payload[0] >> 4) != 0x4))
	{
		tunnel_log(SIXXSD_TUNNEL_NONE, in_tid, SIXXSD_TERR_TUN_PAYLOAD_NOT_IPV4, src);
		return;
	}

	/* Get current time and then the time difference with that from the packet */
 	currtime = gettime();
	i = currtime - ntohl(s->ayh.ayh_epochtime);

	/* The clock may be faster, thus flip the sign */
	if (i < 0) i = -i;

	/* Compare the clock offset */
	if (i > MAX_CLOCK_OFF)
	{
		tunnel_log(SIXXSD_TUNNEL_NONE, in_tid, SIXXSD_TERR_TUN_CLOCK_OFF, src);
		return;
	}

	/* Save their hash */
	memcpy(&their_hash, &s->hash, sizeof(their_hash));

	/* Copy in our SHA1 hash */
	memcpy(&s->hash, &tun->ayiya_sha1, sizeof(s->hash));

	/* Generate a SHA1 of the header + identity + shared secret */
	SHA1_Init(&sha1);
	/* Hash the Packet */
	SHA1_Update(&sha1, (unsigned char *)s, len, shatmp);
	/* Store the hash */
	SHA1_Final(our_hash, &sha1);

	/* Generate a SHA1 of the header + identity + shared secret */
	/* Compare the SHA1's */
	if (memcmp(&their_hash, &our_hash, sizeof(their_hash)) != 0)
	{
		tunnel_log(SIXXSD_TUNNEL_NONE, in_tid, SIXXSD_TERR_TUN_HASHFAIL, src);
		return;
	}

	/* Update the interface */
	tun->state		= SIXXSD_TSTATE_UP;
	tun->lastbeat		= currtime;
	tun->ayiya_af		= af;
	tun->ayiya_protocol	= protocol;
	tun->ayiya_port_us	= dport;
	tun->ayiya_port_them	= sport;
	memcpy(&tun->ip_them, src, sizeof(tun->ip_them));

	if (s->ayh.ayh_opcode == ayiya_op_forward)
	{
		plen = len - (sizeof(*s) - sizeof(s->payload));

		if (s->ayh.ayh_nextheader == IPPROTO_IPV6)
		{
			/* Account the packet */
			tunnel_account_packet_in(in_tid, plen);

			/* Forward it, not an error, do decrease TTL, do a source check */
			iface_route6(in_tid, SIXXSD_TUNNEL_NONE, s->payload, plen, false, true, false);
			return;
		}
		else if (s->ayh.ayh_nextheader == IPPROTO_IPV4)
		{
			/* Account the packet */
			tunnel_account_packet_in(in_tid, plen);

			/* Forward it, not an error, do decrease TTL, do a source check */
			iface_route4(in_tid, SIXXSD_TUNNEL_NONE, s->payload, plen, false, true, false);
			return;
		}
		else
		{
			tunnel_log(SIXXSD_TUNNEL_NONE, in_tid, SIXXSD_TERR_AYIYA_INVALIDFORWARD, src);
		}
	}
	else if (s->ayh.ayh_opcode == ayiya_op_noop)
	{
		/* Silence about this, most likely just used for beating */
	}
}

