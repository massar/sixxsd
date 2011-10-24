/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2011 All Rights Reserved
************************************************************
 $Author: $
 $Id: $
 $Date: $
***********************************************************/

#include "sixxsd.h"

const char module_tunnel[] = "tunnel";
#define module module_tunnel

const char *tunnel_type_name(enum sixxsd_tunnel_type type)
{
	const char *types[] =
	{
		"none",
		"ignore",
		"proto41",
		"heartbeat",
		"ayiya",
	};

	return type < lengthof(types) ? types[type] : "<unknown>";
}

const char *tunnel_state_name(enum sixxsd_tunnel_state state)
{
	const char *states[] =
	{
		"none",
		"disabled",
		"down",
		"up",
	};

	return state < lengthof(states) ? states[state] : "<unknown>";
}

const char *tunnel_error_name(unsigned int err);
const char *tunnel_error_name(unsigned int err)
{
	const char *errs[] =
	{
	/*	 012345678901234567890 */
		"Disabled tunnel",
		"Clock Off",
		"Hash Fail",
		"Encap.Pkt Too Big",
		"Encap.Pkt Send Error",
		"Wrong Source IPv6",
		"Wrong Source IPv4",
		"Non-IPv6 Payload",
		"Non-IPv4 Payload",
		"AYIYA-non-AYIYA",
		"Invalid Forward",
		"HB-non-HB",
		"HB Missing IPv4",
		"HB Sender Mismatch",
		"HB Missing Time",
	};

	return (err < lengthof(errs) ? errs[err] : "<unknown>");
}

struct sixxsd_tunnel *tunnel_grab(const uint16_t tid)
{
	return tid <= g_conf->tunnels.tunnel_hi ? &g_conf->tunnels.tunnel[tid] : NULL;
}

uint16_t tunnel_get(IPADDRESS *addr, BOOL *is_tunnel)
{
	struct sixxsd_tunnels	*t = &g_conf->tunnels;
	uint16_t		tid;

	*is_tunnel = false;

	/* Only look at the first 48 bits to match the prefix */
	if (memcmp(&t->prefix, addr, (48/8)) != 0) return SIXXSD_TUNNEL_NONE;

	/* Bits 48-63 describe the tunnel id */
	tid = ntohs(addr->a16[(48/16)]);
	if (tid <= t->tunnel_hi)
	{
		*is_tunnel = true;
		return tid;
	}

	/* If the high-bit is set it it is a /64 subnet from the tunnel range */
	if (tid && 0x8000)
	{
		tid -= 0x8000;
		if (tid <= t->tunnel_hi) return tid;
	}
	/* Otherwise it is not there */
	else
	{
		char buf[64];
		inet_ntopA(addr, buf, sizeof(buf));
		mdolog(LOG_ERR, "tunnel_get(%s) is out of tunnel range\n", buf);
	}

	return SIXXSD_TUNNEL_NONE;
}

VOID tunnel_debug(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, const char *fmt, ...)
{
	/* Toggled globally when something is debugging or not */
	if (!g_conf->debugging)
	{
		return;
	}
	else
	{
		struct sixxsd_tunnel	*intun, *outtun;
		struct sixxsd_context	*ctx;
		va_list			ap;
		char 			src[NI_MAXHOST], dst[NI_MAXHOST], buf[256];
		struct ip		*ip = (struct ip *)packet;
		struct ip6_hdr		*ip6 = (struct ip6_hdr *)packet;
		unsigned int		ttl = 0;
		int			k;
		uint32_t		plen = 0;
		uint8_t			proto = 0;
		uint8_t			ver = 0;

		/* Are neither of these tunnels involved in debugging? */
		intun = tunnel_grab(in_tid);
		outtun = tunnel_grab(out_tid);

		if (intun && intun->debug_ctx) ctx = intun->debug_ctx;
		else if (outtun && outtun->debug_ctx) ctx = outtun->debug_ctx;
		else return;

		if (packet && len > 20 && (ip->ip_v == 4 || ip->ip_v == 6))
		{
			ver = ip->ip_v;
			if (ver == 4)
			{
				inet_ntopA((IPADDRESS *)&ip6->ip6_src, src, sizeof(src));
				inet_ntopA((IPADDRESS *)&ip6->ip6_dst, dst, sizeof(dst));
				ttl = ip->ip_ttl;
				proto = ip->ip_p;
				plen = ip->ip_len;
			}
			else
			{
				struct ip6_ext *ipe;

				inet_ntopA((IPADDRESS *)&ip6->ip6_src, src, sizeof(src));
				inet_ntopA((IPADDRESS *)&ip6->ip6_dst, dst, sizeof(dst));
				ttl = ip6->ip6_hlim;

				l3_ipv6_parse(packet, len, &proto, &ipe, &plen);
			}
		}
		else
		{
			snprintf(src, sizeof(src), "no packet");
			snprintf(dst, sizeof(dst), "data");
		}


		k = snprintf(buf, sizeof(buf),
			"[T%-5u T%-5u][IPv%u : %-24s - %-24s ttl=%3u proto=%2u len=%-4u plen=%-4u] ",
			intun ? intun->tunnel_id : 0,
			outtun ? outtun->tunnel_id : 0,
			ver,
			src, dst, ttl, proto, len, plen);

		if (!snprintfok(k, sizeof(buf))) k = snprintf(buf, sizeof(buf), "(long line)");

		va_start(ap, fmt);
		vsnprintf(&buf[k], sizeof(buf) - k, fmt, ap);
		va_end(ap);

		ctx_lock(ctx);
		ctx_printf(ctx, "%s", buf);
		ctx_flush(ctx, 200);
		ctx_release(ctx);

		assert(plen < 30000);
	}
}

VOID tunnel_log(const uint16_t in_tid, const uint16_t out_tid, enum sixxsd_tunnel_errors err, const IPADDRESS *src)
{
	struct sixxsd_tunnel	*tun;
	uint16_t		tid;

	/* Select the TID that is a real actual tunnel */
	tid = (out_tid == SIXXSD_TUNNEL_NONE || out_tid == SIXXSD_TUNNEL_UPLINK) ? in_tid : out_tid;

	tun = tunnel_grab(tid);
	if (!tun)
	{
		char hst[64];
		if (src) inet_ntopA(src, hst, sizeof(hst));
		else snprintf(hst, sizeof(hst), "<unknown>");
		mdolog(LOG_ERR, "tunnel_log(%u(%u->%u)/%u/%s) for unknown tunnel\n", tid, in_tid, out_tid, err, hst);
		return;
	}

	/* This error happened again */
	tun->errors[err].count++;

	/* The last time and IP we got it from */
	tun->errors[err].last_seen = gettime();
	if (src) memcpy(&tun->errors[err].last_ip, src, sizeof(tun->errors[err].last_ip));

	if (g_conf->debugging)
	{
		char hst[64];

		if (src) inet_ntopA(src, hst, sizeof(hst));
		else snprintf(hst, sizeof(hst), "<unknown>");

		tunnel_debug(in_tid, out_tid, NULL, 0, "tunnel_log(%s, cnt=%" PRIu64 ") src = %s\n", tunnel_error_name(err), tun->errors[err].count, hst);
	}
}

VOID tunnel_log4(const uint16_t in_tid, const uint16_t out_tid, enum sixxsd_tunnel_errors err, struct in_addr *src)
{
	IPADDRESS ip;

	memcpy(&ip.a8[0], ipv4_mapped_ipv6_prefix, sizeof(ipv4_mapped_ipv6_prefix));
	memcpy(&ip.a8[12], src, 4);

	tunnel_log(in_tid, out_tid, err, &ip);
}

VOID tunnel_update_stat(struct sixxsd_traffic *t, unsigned int packetlen, uint64_t currtime);
VOID tunnel_update_stat(struct sixxsd_traffic *t, unsigned int packetlen, uint64_t currtime)
{
	t->last = currtime;
	t->packets++;
	t->octets += packetlen;
}

VOID tunnel_account_pkt(const uint16_t tid, unsigned int a, unsigned int direction, unsigned int packetlen);
VOID tunnel_account_pkt(const uint16_t tid, unsigned int a, unsigned int direction, unsigned int packetlen)
{
	struct sixxsd_tunnel	*tun;
	struct sixxsd_stats	*s;
	uint64_t		currtime = gettime();

	assert(a < 2);
	assert(direction < 2);

	/* Grab the tunnel these packets are for */
	tun = tunnel_grab(tid);

	/* If it is not a tunnel, it must be the uplink */
	s = tun ? &tun->stats : &g_conf->stats_uplink;

	tunnel_update_stat(&s->traffic[a][direction], packetlen, currtime);
	tunnel_update_stat(&g_conf->stats_total.traffic[a][direction], packetlen, currtime);
}

VOID tunnel_account_packet(const uint16_t in_tid, const uint16_t out_tid, unsigned int af, unsigned int packetlen)
{
	unsigned int	a = af == AF_INET ? 0 : 1;

	tunnel_account_pkt(in_tid,	a, 0, packetlen);
	tunnel_account_pkt(out_tid,	a, 1, packetlen);
}

BOOL tunnel_state_check(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, BOOL is_error)
{
	struct sixxsd_tunnel	*tun;
	unsigned int		code;

	tun = tunnel_grab(out_tid);
	if (!tun) return true;

	/* Interface must be 'up' for it to work */
	/* It will go up when there passes a packet through the tunnel during ayiya_in() or hb_in() */
	switch (tun->state)
	{
	case SIXXSD_TSTATE_UP:
		/* This is what we want */
		return true;

	case SIXXSD_TSTATE_DISABLED:
		code = ICMP6_DST_UNREACH_ADMIN;
		break;

	case SIXXSD_TSTATE_DOWN:
		code = ICMP6_DST_UNREACH_NOROUTE;
		break;

	case SIXXSD_TSTATE_NONE:
	default:
		code = ICMP6_DST_UNREACH_ADDR;
		break;
	}

	if (!is_error) iface_send_icmpv6_unreach(in_tid, out_tid, packet, len, code);

	return false;
}

/* 
 * 0	<tid>					=> tid (2001:db8:ff00:%x::{12}/64)
 * 1	T<tunnel_id>				=> TunnelID (T<xxxx>)
 * 2	<tunnel_them|ayiya|heartbeat>		=> type + tun->ip_them
 * 3	<up|disabled>				=> state
 * 4	<mtu>					=> tun->mtu
 * 5	[<password>]				=> hb_password + hashes
 */
int tunnel_cmd_set_config(struct sixxsd_context *ctx, const unsigned int argc, const char *args[]);
int tunnel_cmd_set_config(struct sixxsd_context *ctx, const unsigned int argc, const char *args[])
{
	struct sixxsd_tunnel	*tun;
	uint16_t		tid;
	SHA_CTX			sha1;
	unsigned int		i, tmp;

	if (sscanf(args[0], "%x", &tmp) != 1)
	{
		ctx_printf(ctx, "Invalid TID (%s) - not a hex number\n", args[0]);
		return 400;
	}
	tid = tmp;

	if (tid > lengthof(g_conf->tunnels.tunnel))
	{
		ctx_printf(ctx, "TID 0x%x is out of range (0x%u) in line \n", tid, (unsigned int)lengthof(g_conf->tunnels.tunnel));
		return 400;
	}

	tun = &g_conf->tunnels.tunnel[tid];

	/* Update the Hi Tunnel marker */
	if (tid > g_conf->tunnels.tunnel_hi) g_conf->tunnels.tunnel_hi = tid;

	if (sscanf(args[1], "T%u", &tmp) != 1)
	{
		ctx_printf(ctx, "Invalid Tunnel ID (%s) - not a number\n", args[1]);
		return 400;
	}
	tun->tunnel_id = tmp;

	if (sscanf(args[4], "%u", &tmp) != 1)
	{
		ctx_printf(ctx, "Invalid Tunnel MTU (%s) - not a number\n", args[4]);
		return 400;
	}
	tun->mtu = tmp;

	if (tun->mtu < 1280 || tun->mtu > 1480)
	{	
		ctx_printf(ctx, "Tunnel MTU %u is outside range (1280-1480)\n", tun->mtu);
		return 400;
	}

	if	(strcasecmp(args[2], "ayiya"		) == 0) tun->type = SIXXSD_TTYPE_AYIYA;
	else if (strcasecmp(args[2], "heartbeat"	) == 0) tun->type = SIXXSD_TTYPE_PROTO41_HB;
	else
	{
		tun->type = SIXXSD_TTYPE_PROTO41;

		if (!inet_ptonA(args[2], &tun->ip_them, NULL))
		{
			ctx_printf(ctx, "Invalid Tunnel_Them address (%s)\n", args[2]);
			return 400;
		}
	}

	if (tun->type == SIXXSD_TTYPE_PROTO41)
	{
		tun->state = strcasecmp(args[3], "disabled") == 0 ? SIXXSD_TSTATE_DISABLED : SIXXSD_TSTATE_UP;
	}
	else
	{
		/* Dynamic tunnels can be Disabled, Up or Down */
		if (strcasecmp(args[3], "disabled") == 0) tun->state = SIXXSD_TSTATE_DISABLED;
		/* Not down or up? Make it down */
		else if (tun->state != SIXXSD_TSTATE_DOWN && tun->state != SIXXSD_TSTATE_UP) tun->state = SIXXSD_TSTATE_DOWN;
	}

	if (argc == 7)
	{
		i = strlen(args[5]);
		if ((i+1) > sizeof(tun->hb_password))
		{
			ctx_printf(ctx, "Password given (%s) is too long (%u/%u)\n", args[5], i, (unsigned int)sizeof(tun->hb_password));
			return 400;
		}

		/* Heartbeat/AYIYA Password */
		memzero(tun->hb_password, sizeof(tun->hb_password));
		memcpy((char *)tun->hb_password, args[5], i);

		/* Pre-generate AYIYA SHA1 hash */
		SHA1_Init(&sha1);
		SHA1_Update(&sha1, tun->hb_password, i);
		SHA1_Final(tun->ayiya_sha1, &sha1);
	}

	ctx_printf(ctx, "Accepted Tunnel %x/T%u%s\n", tid, tun->tunnel_id, argc == 5 ? " with password" : "");
	return 200;
}

int tunnel_cmd_list(struct sixxsd_context *ctx, const unsigned int argc, const char *args[]);
int tunnel_cmd_list(struct sixxsd_context *ctx, const unsigned int argc, const char *args[])
{
	struct sixxsd_tunnels	*tuns = &g_conf->tunnels;
	struct sixxsd_tunnel	*tun;
	unsigned int		tid, count = 0, i, theerr = 0;
	uint64_t		errorcount = 0;
	char			hst[NI_MAXHOST];
	BOOL			erroronly = false, errspec = false, debugonly = false;

	if (argc == 1)
	{
		if	(strcasecmp(args[0], "all"	) == 0) { erroronly = false;	errspec = false;	debugonly = false;	}
		else if (strcasecmp(args[0], "debugonly") == 0) { erroronly = false;	errspec = false;	debugonly = true;	}
		else if (strcasecmp(args[0], "erroronly") == 0) { erroronly = true;	errspec = false;	debugonly = false;	}
		else if (strncasecmp(args[0], "err=", 4) == 0)
		{
			for (theerr = 0; theerr < SIXXSD_TERR_MAX; theerr++)
			{
				if (strcasecmp(&args[0][4], tunnel_error_name(theerr)) == 0) break;
			}

			if (theerr >= SIXXSD_TERR_MAX)
			{
				ctx_printf(ctx, "Unknown error \"%s\"\n", &args[0][4]);
				return 400;
			}

			errspec = true;
		}
		else
		{
			ctx_printf(ctx, "Unknown option '%s'\n", args[0]);
			return 400;
		}
	}

	for (tid = 0; tid <= tuns->tunnel_hi; tid++)
	{
		tun = tunnel_grab(tid);
		if (tun->state == SIXXSD_TSTATE_NONE) continue;

		if (debugonly && !tun->debug_ctx) continue;

		if (errspec)
		{
			if (tun->errors[theerr].count == 0) continue;
			errorcount = tun->errors[theerr].count;
		}
		else
		{
			errorcount = 0;
			for (i = 0; i < lengthof(tun->errors); i++)
			{
				errorcount += tun->errors[i].count;
			}
		}

		if (erroronly && errorcount == 0) continue;

		inet_ntopA(&tun->ip_them, hst, sizeof(hst));

		ctx_printf(ctx, "T%u %s%x::2 %s %s %s %u %" PRIu64 "\n", tun->tunnel_id, tuns->prefix_asc, tid, hst, tunnel_state_name(tun->state), tunnel_type_name(tun->type), tun->mtu, errorcount);
		count++;
	}

	if (count == 0)
	{
		ctx_printf(ctx, "No tunnels are configured%s\n",
			debugonly	? " which are in debugging mode" :
			erroronly	? " which have errors" :
			errspec		? " which have the requested error" :
					  "");
	}

	return 200;
}

VOID tunnel_ago(struct sixxsd_context *ctx, uint64_t when, const char *fmt, ...) ATTR_FORMAT(printf, 3, 4);
VOID tunnel_ago(struct sixxsd_context *ctx, uint64_t when, const char *fmt, ...)
{
	unsigned int	ago_s, ago_m, ago_h, ago_d;
	uint64_t	now = gettime();
	time_t		t;
	struct tm	teem;
	char		buf[128], prefix[128];
	va_list		ap;

	va_start(ap, fmt);
	vsnprintf(prefix, sizeof(prefix), fmt, ap);
	va_end(ap);

	if (when == 0)
	{
		ctx_printdf(ctx, "%snever\n", prefix);
		return;
	}

	/* Beats cannot be in the future, but we might race ourselves */
	if (when > now) when = now;

	ago_s  = now - when;
	ago_d  = ago_s / (24*60*60);
	ago_s -= ago_d *  24*60*60;
	ago_h  = ago_s / (60*60);
	ago_s -= ago_h *  60*60;
	ago_m  = ago_s /  60;
	ago_s -= ago_m *  60;

	t = when;
	gmtime_r(&t, &teem);
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &teem);

	ctx_printdf(ctx, "%s%s (%" PRIu64 "; %u days %02u:%02u:%02u ago)\n", prefix, buf, when, ago_d, ago_h, ago_m, ago_s);
}

int tunnel_show(struct sixxsd_context *ctx, uint16_t tid);
int tunnel_show(struct sixxsd_context *ctx, uint16_t tid)
{
	struct sixxsd_tunnels	*tuns = &g_conf->tunnels;
	struct sixxsd_tunnel	*tun;
	char			buf[512];
	unsigned int		a, d;
	const char		as[2][5] = { "IPv4", "IPv6" };
	const char		ds[2][5] = { "In", "Out" };

	tun = tunnel_grab(tid);
	if (!tun)
	{
		ctx_printf(ctx, "No such tunnel %x\n", tid);
		return 404;
	}

	ctx_printf(ctx, "Tunnel ID               : T%u\n", tun->tunnel_id);
	ctx_printf(ctx, "TID                     : 0x%x\n", tid);
	ctx_printf(ctx, "Tunnel Debugging        : %s%s\n", yesno(tun->debug_ctx), tun->debug_ctx && !g_conf->debugging ? " [PoP-wide disabled]" : "");
	ctx_printf(ctx, "Inner Us                : %s%x::1\n", tuns->prefix_asc, tid);
	ctx_printf(ctx, "Inner Them              : %s%x::2\n", tuns->prefix_asc, tid);

	inet_ntopA(&g_conf->pop_ipv4, buf, sizeof(buf));
	ctx_printf(ctx, "Outer Us                : %s\n", buf);

	inet_ntopA(&tun->ip_them, buf, sizeof(buf));
	ctx_printf(ctx, "Outer Them              : %s\n", buf);

	ctx_printf(ctx, "MTU                     : %u\n", tun->mtu);
	ctx_printf(ctx, "Tunnel State            : %s\n", tunnel_state_name(tun->state));
	ctx_printf(ctx, "Tunnel Type             : %s\n", tunnel_type_name(tun->type));

	/* AYIYA details */
	if (tun->type == SIXXSD_TTYPE_AYIYA)
	{
		ctx_printf(ctx, "AYIYA AF                : %u\n", tun->ayiya_af);
		ctx_printf(ctx, "AYIYA Protocol          : %u\n", tun->ayiya_protocol);
		ctx_printf(ctx, "AYIYA Port Us           : %u\n", tun->ayiya_port_us);
		ctx_printf(ctx, "AYIYA Port Them         : %u\n", tun->ayiya_port_them);
		ctx_printf(ctx, "AYIYA Hash Type         : %u\n", tun->ayiya_hash_type);
	}

	/* When the last heartbeat was seen */
	if (tun->type == SIXXSD_TTYPE_AYIYA || tun->type == SIXXSD_TTYPE_PROTO41_HB)
	{
		tunnel_ago(ctx, tun->lastbeat, "Last Heartbeat          : ");
		ctx_printf(ctx, "Heartbeat Password      : %s\n", tun->hb_password);
	}

	/* Show the packets in/out per IP version */
	for (a = 0; a < 2; a++)
	{
		for (d = 0; d < 2; d++)
		{
			tunnel_ago(ctx, tun->stats.traffic[a][d].last, "%4s Packet %-3s         : ", as[a], ds[d]);
			ctx_printf(ctx, "%4s Packets %-3s        : %" PRIu64 "\n", as[a], ds[d], tun->stats.traffic[a][d].packets);
			ctx_printf(ctx, "%4s Octets %-3s         : %" PRIu64 "\n", as[a], ds[d], tun->stats.traffic[a][d].octets);
		}

		/* Current latency information */
		ctx_printf(ctx, "%4s Latency Pkt Sent   : %u\n",	as[a], tun->stats.latency[a].num_sent);
		ctx_printf(ctx, "%4s Latency Pkt Recv   : %u\n",	as[a], tun->stats.latency[a].num_recv);

		if (tun->stats.latency[a].num_sent > 0 && tun->stats.latency[a].num_recv > 0)
		{
			ctx_printf(ctx, "%4s Latency Loss       : %2.2f\n",	as[a], tun->stats.latency[a].num_sent == 0 ? 0 : (float)(tun->stats.latency[a].num_sent - tun->stats.latency[a].num_recv) * 100 / tun->stats.latency[a].num_sent);
			ctx_printf(ctx, "%4s Latency Min        : %2.2f ms\n",	as[a], time_us_msec(tun->stats.latency[a].min));
			ctx_printf(ctx, "%4s Latency Avg        : %2.2f ms\n",	as[a], time_us_msec(tun->stats.latency[a].tot / (tun->stats.latency[a].num_recv == 0 ? 1 : tun->stats.latency[a].num_recv)));
			ctx_printf(ctx, "%4s Latency Max        : %2.2f ms\n",	as[a], time_us_msec(tun->stats.latency[a].max));
		}
	}

	/* Show the errors */
	for (a = 0; a < SIXXSD_TERR_MAX; a++)
	{
		if (tun->errors[a].count == 0)
		{
			ctx_printf(ctx, "%-24s: none\n", tunnel_error_name(a));
		}
		else
		{
			inet_ntopA(&tun->errors[a].last_ip, buf, sizeof(buf));
			tunnel_ago(ctx, tun->errors[a].last_seen, "%-24s: %" PRIu64 ", last: %s ", tunnel_error_name(a), tun->errors[a].count, buf);
		}
	}

	return 200;
}

int tunnel_gettid(struct sixxsd_context *ctx, const char *arg, uint16_t *tid_);
int tunnel_gettid(struct sixxsd_context *ctx, const char *arg, uint16_t *tid_)
{
	IPADDRESS	ip;
	BOOL		is_tunnel;
	uint16_t	tid;

	/* None found yet */
	*tid_ = tid = SIXXSD_TUNNEL_NONE;

	/* Is it an IPv6 address? */
	if (inet_ptonA(arg, &ip, NULL))
	{
		tid = address_find(&ip, &is_tunnel);
	}
	else
	{
		unsigned int i, j;

		/* Is it maybe an interface number? */
		if (sscanf(arg, "T%u", &i) != 1)
		{
			ctx_printf(ctx, "It would be nice if you provided a proper IP address or Tunnel ID (eg T<xxx>) and not '%s'\n", arg);
			return 400;
		}

		for (j = 0; j <= g_conf->tunnels.tunnel_hi; j++)
		{
			if (g_conf->tunnels.tunnel[j].tunnel_id != i) continue;
			tid = j;
			break;
		}

		if (tid == SIXXSD_TUNNEL_NONE)
		{
			ctx_printf(ctx, "No such Tunnel ID (T%u/%s) found\n", i, arg);
			return 404;
		}

		if (!tunnel_grab(tid))
		{
			ctx_printf(ctx, "Interface %s/%x does not exist\n", arg, tid);
			return 404;
		}
	}

	if (tid == SIXXSD_TUNNEL_NONE)
	{
		ctx_printf(ctx, "No such tunnel %s\n", arg);
		return 404;
	}

	*tid_ = tid;
	return 200;
}

int tunnel_cmd_show(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[]);
int tunnel_cmd_show(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[])
{
	uint16_t	tid;
	int		ret;

	ret = tunnel_gettid(ctx, args[0], &tid);
	if (ret != 200) return ret;

	if (tid == SIXXSD_TUNNEL_NONE)
	{
		ctx_printf(ctx, "No such address on this system\n");
		return 404;
	}

	return tunnel_show(ctx, tid);
}

int tunnel_cmd_get_outer_endpoint(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[]);
int tunnel_cmd_get_outer_endpoint(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[])
{
	uint16_t		tid;
	int			ret;
	char			buf[64];
	struct sixxsd_tunnel	*tun;

	ret = tunnel_gettid(ctx, args[0], &tid);
	if (ret != 200) return ret;

	if (tid == SIXXSD_TUNNEL_NONE)
	{
		ctx_printf(ctx, "No such address on this system\n");
		return 404;
	}

	tun = tunnel_grab(tid);
	if (!tun)
	{
		ctx_printf(ctx, "Tunnel not configured\n");
		return 404;
	}

	inet_ntopA(&tun->ip_them, buf, sizeof(buf));
	ctx_printf(ctx, "%s\n", buf);

	return 200;
}

VOID tunnel_stats(struct sixxsd_context *ctx, const char *name, unsigned int version, struct sixxsd_traffic *in, struct sixxsd_traffic *out, struct sixxsd_latency *latency);
VOID tunnel_stats(struct sixxsd_context *ctx, const char *name, unsigned int version, struct sixxsd_traffic *in, struct sixxsd_traffic *out, struct sixxsd_latency *latency)
{
	/* Nothing counted then we don't need to show stats either */
	if (in->packets == 0 && out->packets == 0) return;

	/* Name | IPvX | InOct | OutOct | InPkt | OutPkt | PktSent | PktRecv | Loss | Min | Avg | Max */
	ctx_printf(ctx, "%s %u %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "%s",
			name,
			version,
			in->octets,
			out->octets,
			in->packets,
			out->packets,
			latency ? "" : "\n");

	if (!latency) return;

	ctx_printf(ctx, " %u %u %2.2f %2.2f %2.2f %2.2f\n",
			latency->num_sent,
			latency->num_recv,
			latency->num_sent == 0 ? 0 : (float)(latency->num_sent - latency->num_recv) * 100 / latency->num_sent,
			latency->num_recv == 0 ? -1 : time_us_msec(latency->min),
			latency->num_recv == 0 ? -1 : time_us_msec(latency->tot / latency->num_recv),
			latency->num_recv == 0 ? -1 : time_us_msec(latency->max)
	);
}

int tunnel_cmd_stats(struct sixxsd_context *ctx, const unsigned int argc, const char *args[]);
int tunnel_cmd_stats(struct sixxsd_context *ctx, const unsigned int argc, const char *args[])
{
	struct sixxsd_tunnels	*t = &g_conf->tunnels;
	struct sixxsd_tunnel	*tun;
	uint64_t		count = 0;
	uint16_t		tid;
	BOOL			reset = false;
	char 			name[32];

	if (argc == 1 && strcmp(args[0], "RESET") == 0) reset = true;

	snprintf(name, sizeof(name), "total");
	tunnel_stats(ctx, name, 4, &g_conf->stats_total.traffic[stats_ipv4][stats_in], &g_conf->stats_total.traffic[stats_ipv4][stats_out], NULL);
	tunnel_stats(ctx, name, 6, &g_conf->stats_total.traffic[stats_ipv6][stats_in], &g_conf->stats_total.traffic[stats_ipv6][stats_out], NULL);
	if (reset) memzero(&g_conf->stats_total, sizeof(g_conf->stats_total));

	snprintf(name, sizeof(name), "uplink");
	tunnel_stats(ctx, name, 4, &g_conf->stats_uplink.traffic[stats_ipv4][stats_in], &g_conf->stats_uplink.traffic[stats_ipv4][stats_out], NULL);
	tunnel_stats(ctx, name, 6, &g_conf->stats_uplink.traffic[stats_ipv6][stats_in], &g_conf->stats_uplink.traffic[stats_ipv6][stats_out], NULL);
	if (reset) memzero(&g_conf->stats_uplink, sizeof(g_conf->stats_uplink));

	/* Grab the write mutex, to avoid the pinger from pinging more and messing up our stats ;) */
	mutex_lock(g_conf->mutex_pinger);

	for (tid = 0; tid <= t->tunnel_hi; tid++)
	{
		count++;
		tun = &t->tunnel[tid];

		/* Name of the interface */
		snprintf(name, sizeof(name), "T%u", tun->tunnel_id);

		/* IPv4 + IPv6 statistics */
		tunnel_stats(ctx, name, 4, &tun->stats.traffic[stats_ipv4][stats_in], &tun->stats.traffic[stats_ipv4][stats_out], &tun->stats.latency[stats_ipv4]);
		tunnel_stats(ctx, name, 6, &tun->stats.traffic[stats_ipv6][stats_in], &tun->stats.traffic[stats_ipv6][stats_out], &tun->stats.latency[stats_ipv6]);

		/* Reset them */
		if (reset)
		{
			memzero(tun->stats.traffic, sizeof(tun->stats.traffic));
			reset_latency(&tun->stats.latency[stats_ipv4]);
			reset_latency(&tun->stats.latency[stats_ipv6]);
		}
	}

	/* Release it so that the pinger can do it's work */
	mutex_release(g_conf->mutex_pinger);

	/* All okay */
	if (count != 0) return 200;

	/* Nothing there yet */
	ctx_printf(ctx, "No tunnels are configured\n");
	return 404;
}

int tunnel_cmd_set_debug(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char *args[]);
int tunnel_cmd_set_debug(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char *args[])
{
	struct sixxsd_tunnel	*tun;
	uint16_t		tid;
	int			ret;

	ret = tunnel_gettid(ctx, args[0], &tid);
	if (ret != 200) return ret;

	if (tid == SIXXSD_TUNNEL_NONE)
	{
		ctx_printf(ctx, "No such tunnel on this system\n");
		return 404;
	}

	tun = tunnel_grab(tid);
	if (!tun)
	{
		ctx_printf(ctx, "Tunnel went missing!?\n");
		return 404;
	}

	/* Enable debugging or not */
	if (isyes(args[1]))
	{
		if (tun->debug_ctx == ctx)
		{
			ctx_printf(ctx, "Debugging through this session for this tunnel was already enabled\n");
			return 400;
		}
		else if (tun->debug_ctx != NULL)
		{
			ctx_printf(ctx, "Already being debugged by another session\n");
			return 400;
		}

		/* Enable debugging */
		tun->debug_ctx = ctx;
		ctx_lock(ctx);
		ctx->debugging_tunnels++;
		ctx_release(ctx);
		g_conf->debugging++;
		ctx_printf(ctx, "Debugging has been enabled\n");
	}
	else
	{
		assert(g_conf->debugging > 0);
		g_conf->debugging--;
		ctx_lock(ctx);
		ctx->debugging_tunnels--;
		ctx_release(ctx);
		tun->debug_ctx = NULL;
		ctx_printf(ctx, "Debugging has been disabled\n");
	}

	return 200;
}


int tunnel_cmd_set_remote(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char *args[]);
int tunnel_cmd_set_remote(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char *args[])
{
	struct sixxsd_tunnel	*tun;
	uint16_t		tid;
	int			ret;

	ret = tunnel_gettid(ctx, args[0], &tid);
	if (ret != 200) return ret;

	if (tid == SIXXSD_TUNNEL_NONE)
	{
		ctx_printf(ctx, "No such tunnel on this system\n");
		return 404;
	}

	tun = tunnel_grab(tid);
	if (!tun)
	{
		ctx_printf(ctx, "Tunnel went missing!?\n");
		return 404;
	}

	if (!inet_ptonA(args[1], &tun->ip_them, NULL))
	{
		ctx_printf(ctx, "Invalid Tunnel_Them address (%s)\n", args[1]);
		return 400;
	}

	tun->ayiya_port_us = tun->ayiya_port_them = AYIYA_PORT;
	tun->state = SIXXSD_TSTATE_UP;

	ctx_printf(ctx, "Updated remote address to %s\n", args[1]);

	return 200;
}

PTR *tunnel_beat_check(PTR UNUSED *arg);
PTR *tunnel_beat_check(PTR UNUSED *arg)
{
	struct sixxsd_tunnels	*t = &g_conf->tunnels;
	struct sixxsd_tunnel	*tun;
	uint16_t		tid;
	uint64_t		currtime = gettime();

	while (g_conf && g_conf->running)
	{
		for (tid = 0; tid <= t->tunnel_hi; tid++)
		{
			tun = &t->tunnel[tid];

			if (tun->state != SIXXSD_TSTATE_UP) continue;

			if (tun->type != SIXXSD_TTYPE_PROTO41_HB && tun->type != SIXXSD_TTYPE_AYIYA) continue;

			/* It beat recently? */
			if (tun->lastbeat > currtime) continue;
			if ((currtime - tun->lastbeat) < MAX_CLOCK_OFF) continue;

			/* Disable it */
			tun->state = SIXXSD_TSTATE_DOWN;
		}

		/* Sleep for 10 seconds, then try again */
		thread_sleep(10,0);
	}

	return NULL;
}

int tunnel_init(struct sixxsd_context *ctx)
{
	if (!thread_add(ctx, "TunnelBeatCheck", tunnel_beat_check, NULL, NULL, true)) return 400;

	return 200;
}

struct ctx_menu ctx_menu_tunnel_get[] =
{
	{"get",			NULL,				0,0,	NULL,	NULL },
	{"outer_endpoint",	tunnel_cmd_get_outer_endpoint,	0,0,	NULL,	"Get the current outer endpoint" },
	{NULL,			NULL,				0,0,	NULL,	NULL },
};

struct ctx_menu ctx_menu_tunnel_set[] =
{
	{"set",			NULL,				0,0,	NULL,											NULL },
	{"config",		tunnel_cmd_set_config,		5,6,	"<tid> <tunnel-id> <tunnel_them|ayiya|heartbeat> <up|disabled> <mtu> [<password>]",	"Configure a tunnel" },
	{"debug",		tunnel_cmd_set_debug,		2,2,	"<tid> {on|off}",									"Enable/Disable debugging" },
	{"remote",		tunnel_cmd_set_remote,		2,2,	"<tid> <ip>",										"Set the remote address" },
	{NULL,			NULL,				0,0,	NULL,											NULL },
};

CONTEXT_MENU(tunnel_get)
CONTEXT_CMD(tunnel_get)
CONTEXT_MENU(tunnel_set)
CONTEXT_CMD(tunnel_set)

struct ctx_menu ctx_menu_tunnel[] =
{
	{"tunnel",	NULL,			0,0,	NULL,			NULL },
        {"get",		ctx_cmd_tunnel_get,	0,-1,	CONTEXT_SUB,		"Get configuration information" },
        {"set",		ctx_cmd_tunnel_set,	0,-1,	CONTEXT_SUB,		"Set configuration information" },
	{"show",	tunnel_cmd_show,	1,1,	"<ip>",			"Show the configuration of a single tunnel" },
	{"stats",	tunnel_cmd_stats,	0,1,	NULL,			"Get stats for all tunnels" },
	{"list",	tunnel_cmd_list,	0,1,	"[{all|debug|err=X}]",	"List a summary of the tunnels filtered by the given option" },
	{NULL,		NULL,			0,0,	NULL,			NULL },
};

CONTEXT_CMD(tunnel)

