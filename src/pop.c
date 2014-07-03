/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2013 All Rights Reserved
***********************************************************/

#include "sixxsd.h"

const char module_pop[] = "pop";
#define module module_pop

static int pop_cmd_show_version(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[]);
static int pop_cmd_show_version(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[])
{
	ctx_printdf(ctx, "%s %s\n", SIXXSD_DESC, SIXXSD_VERSION);
	ctx_printdf(ctx, "SixXSd %s by Jeroen Massar <jeroen@sixxs.net>\n", SIXXSD_RELEASE);
	ctx_printdf(ctx, "%s\n", SIXXSD_COPYRIGHT);
	ctx_printdf(ctx, "\n");
	ctx_printdf(ctx, "Build Information: %s\n", BUILDINFO);
	ctx_printdf(ctx, "SixXSd Version: %s\n", SIXXSD_VERSION);
	ctx_printdf(ctx, "SixXSd Release: %s\n", SIXXSD_RELEASE);
	ctx_printdf(ctx, "OS/CPU Bits: %u\n", OS_BITS);
	return 200;
}

static VOID pop_uptimeA(struct sixxsd_context *ctx, const char *prefix, unsigned int uptime);
static VOID pop_uptimeA(struct sixxsd_context *ctx, const char *prefix, unsigned int uptime)
{
	unsigned int	uptime_s, uptime_m, uptime_h, uptime_d;

	uptime_s  = uptime;
	uptime_d  = uptime_s / (24*60*60);
	uptime_s -= uptime_d *  24*60*60;
	uptime_h  = uptime_s / (60*60);
	uptime_s -= uptime_h *  60*60;
	uptime_m  = uptime_s /  60;
	uptime_s -= uptime_m *  60;

	ctx_printdf(ctx, "%s%u days %02u:%02u:%02u\n", prefix, uptime_d, uptime_h, uptime_m, uptime_s);
}

static VOID pop_uptime(struct sixxsd_context *ctx, const char *prefix);
static VOID pop_uptime(struct sixxsd_context *ctx, const char *prefix)
{
	pop_uptimeA(ctx, prefix, gettime() - g_conf->starttime);
}

static int pop_cmd_show_uptime(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[]);
static int pop_cmd_show_uptime(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[])
{
	pop_uptime(ctx, "");
	return 200;
}

static int pop_cmd_show_timeinfo(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[]);
static int pop_cmd_show_timeinfo(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[])
{
	struct tm	teem;
	time_t		t, te;
	char		buf[128];

	t = g_conf->starttime; 
	gmtime_r(&t, &teem);
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &teem);
	ctx_printdf(ctx, "Started: %s UTC (%" PRIu64 ")\n", buf, (uint64_t)t);

	te = t = gettime();
	gmtime_r(&te, &teem);
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &teem);
	ctx_printdf(ctx, "Current: %s UTC (%" PRIu64 ")\n", buf, (uint64_t)te);

	ctx_printdf(ctx, "UTC Offset: %d\n", get_utc_offset());

	localtime_r(&t, &teem);
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S %Z", &teem);
	ctx_printdf(ctx, "LocalTime: %s\n", buf);

	pop_uptime(ctx, "Uptime: ");
	return 200;
}

static int pop_cmd_show_unixtime(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[]);
static int pop_cmd_show_unixtime(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[])
{
	ctx_printdf(ctx, "%" PRIu64 "\n", gettime());
	return 200;
}

static int pop_cmd_show_info(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[]);
static int pop_cmd_show_info(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[])
{
	/* Parsed by the UI */
	ctx_printdf(ctx, "PoP Name                : %s\n", g_conf->pop_name);
	ctx_printdf(ctx, "Running                 : %s\n", yesno(g_conf->running));

	ctx_printdf(ctx, "Verbosity Level         : %" PRIu64 "\n", g_conf->verbose);
	ctx_printdf(ctx, "Verbose SixXSd          : %s\n", yesno(g_conf->verbose_sixxsd));
	ctx_printdf(ctx, "        AYIYA           : %s\n", yesno(g_conf->verbose_ayiya));
	ctx_printdf(ctx, "        Common          : %s\n", yesno(g_conf->verbose_common));
	ctx_printdf(ctx, "        Config          : %s\n", yesno(g_conf->verbose_config));
	ctx_printdf(ctx, "        Prefix          : %s\n", yesno(g_conf->verbose_prefix));
	ctx_printdf(ctx, "        Thread          : %s\n", yesno(g_conf->verbose_thread));

	return 200;
}

static int pop_cmd_show_hostinfo(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[]);
static int pop_cmd_show_hostinfo(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[])
{
	const char	*platform = NULL, *version = NULL;
	struct utsname	uts_name;
#ifdef _SC_NPROCESSORS_ONLN
	int		i;
#endif

#ifdef _LINUX
	FILE		*f;
	double		up;
#endif

	uname(&uts_name);
	platform = uts_name.sysname;
	version = uts_name.release;

	ctx_printdf(ctx, "PoP Name: %s\n", g_conf->pop_name);
	ctx_printdf(ctx, "Platform: %s\n", platform);
	ctx_printdf(ctx, "Release: %s\n", version);

#ifdef _LINUX
	f = fopen("/proc/uptime", "r");
	if (f)
	{
		if (fscanf(f, "%lf", &up) == 1) pop_uptimeA(ctx, "Uptime: ", (unsigned int)up);
		else ctx_printdf(ctx, "Uptime: %s\n", "(bad details in /proc/version)");
		fclose(f);
	}
#else
#ifdef _FREEBSD
	struct timespec tp;
	if (clock_gettime(CLOCK_MONOTONIC, &tp) != -1)
	{
		pop_uptimeA(ctx, "Uptime: ", tp.tv_sec);
	}
#else /* _FREEBSD */
	/* OS X does not have clock_gettime, use clock_get_time */
	clock_serv_t    cclock;
	mach_timespec_t mts;

	if (1)
	{
		host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &cclock);
		clock_get_time(cclock, &mts);
		mach_port_deallocate(mach_task_self(), cclock);

		pop_uptimeA(ctx, "Uptime: ", mts.tv_sec);
	}
#endif /* _FREEBSD */
#endif /* _LINUX */
	else
	{
		ctx_printdf(ctx, "Uptime: %s\n", "(not available)");
	}

#ifdef _SC_NPROCESSORS_ONLN
	/* When the system can provide the information, use it */
	i = sysconf(_SC_NPROCESSORS_ONLN);

	if (i != -1)
	{
		ctx_printdf(ctx, "CPU Count: %u\n", i);
	}
#endif

#ifdef _LINUX
	/* Read /proc/cpuinfo for CPU Information */
	f = fopen("/proc/cpuinfo", "r");
	if (f)
	{
		unsigned int	j;
		char		buf[2048];

		while (!feof(f))
		{
			if (fgets(buf, sizeof(buf), f) == NULL) break;

			/* We only want to know the model name */
			if (strncasecmp("model name", buf, 10) != 0) continue;

			/* Skip till the colon */
			for (j=0;j<strlen(buf) && buf[j] != ':';j++);

			/* Remove trailing \n */
			buf[strlen(buf)-1] = '\0';

			ctx_printdf(ctx, "CPU Model: %s\n", &buf[j+2]);

			/* Assume CPU's are all the same */
			break;
		}

		fclose(f);
	}

	/* Read /proc/meminfo for Memory Information */
	f = fopen("/proc/meminfo", "r");
	if (f)
	{
		unsigned int	j;
		uint64_t	l;
		char		buf[2048];

		while (!feof(f))
		{
			if (fgets(buf, sizeof(buf), f) == NULL) break;

			if (strncasecmp("Mem", buf, 3) != 0) continue;

			l = strlen(buf);

			/* Remove trailing \n */
			buf[strlen(buf)-1] = '\0';

			/* Find colon */
			for (j=0; j < strlen(buf) && buf[j] != ':'; j++);

			/* Terminate the label */
			buf[j] = '\0';

			/* Skip whitespace */
			for (j++; j < l && (buf[j] == ' ' || buf[j] == '\t'); j++);

			if (sscanf(&buf[j], "%" PRIu64, &l) != 1)
			{
				ctx_printf(ctx, "[/proc/meminfo contains invalid numbers]\n");
				break;
			}

			l *= 1024;

			ctx_printdf(ctx, "%s: %" PRIu64 "\n", buf, l);
		}

		fclose(f);
	}
#endif

	/*
	 * Return Information from LSB
	 * (we don't look at the return code of the exec,
	 * when it fails, the info is not presented)
	 */
	ctx_shell(ctx, "lsb_release -a 2>/dev/null");

	return 200;
}

static int pop_cmd_show_status(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[]);
static int pop_cmd_show_status(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[])
{
	struct sixxsd_tunnels	*t = &g_conf->tunnels;
	unsigned int		i;
	enum sixxsd_tunnel_type	type;
	uint64_t		onl = 0, act = 0, cfg = 0;
	uint64_t		online[SIXXSD_TTYPE_MAX], active[SIXXSD_TTYPE_MAX], configured[SIXXSD_TTYPE_MAX];
	time_t			now = time(NULL);

	/* Online */
	memzero(online, sizeof(online));
	memzero(active, sizeof(active));
	memzero(configured, sizeof(configured));

	/* Which ones are configured & online? */
	for (i = 0; i <= t->tunnel_hi; i++)
	{
		type = t->tunnel[i].type;

		/* Count the tunnels that are configured (should match tunnel_hi, unless we have ignored ones) */
		configured[type]++;

		/* Count the tunnels that are marked as being UP */
		if (t->tunnel[i].state == SIXXSD_TSTATE_UP) online[type]++;

		/* Active are tunnels that send and received a packet in the last 15 minutes */
		if (	((now - t->tunnel[i].stats.traffic[0].last) < (15*60)) &&
			((now - t->tunnel[i].stats.traffic[0].last) < (15*60)))
		{
			active[type]++;
		}
	}

	for (i = 1; i < lengthof(online); i++)
	{
		ctx_printdf(ctx, "%s %" PRIu64 " %" PRIu64 " %" PRIu64 "\n", tunnel_type_name(i), online[i], active[i], configured[i]);

		onl += online[i];
		act += active[i];
		cfg += configured[i];
	}

	ctx_printdf(ctx, "%s %" PRIu64 " %" PRIu64 " %" PRIu64 "\n", "total", onl, act, cfg);

	return 200;
}

static int pop_cmd_set_verbosity(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char *args[]);
static int pop_cmd_set_verbosity(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char *args[])
{
	uint64_t i;

	if (sscanf(args[0], "%" PRIu64, &i) == 1 && i < 42)
	{
		g_conf->verbose = i;

		ctx_printf(ctx, "Verbosity is now %" PRIu64 "\n", g_conf->verbose);
		return 200;
	}

	ctx_printf(ctx, "Invalid number (%s) given for verbosity (range: 0 - 42)\n", args[0]);
	return 500;
}

/*
 * Configure the parts one wants to see
 * debug (sixxsd|common|prefix|thread) (on|off)
 */
static int pop_cmd_set_debug(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char *args[]);
static int pop_cmd_set_debug(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char *args[])
{
	const char	*what;
	BOOL		to = false;

	what = args[0];

	to = isyes(args[1]);

	if	(strcasecmp(what, "sixxsd"	) == 0) g_conf->verbose_sixxsd		= to;
	else if (strcasecmp(what, "common"	) == 0) g_conf->verbose_common		= to;
	else if (strcasecmp(what, "prefix"	) == 0) g_conf->verbose_prefix		= to;
	else if (strcasecmp(what, "thread"	) == 0) g_conf->verbose_thread		= to;
	else
	{
		ctx_printf(ctx, "\"%s\" is a wrong type for the debug command\n", what);
		return 400;
	}

	ctx_printf(ctx, "Ok\n");

	return 200;
}

static int pop_cmd_saveconfig(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[]);
static int pop_cmd_saveconfig(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[])
{
	FILE			*f;
	char			buf[128];
	const char		*pw;
	unsigned int		i, j;
	struct sixxsd_tunnels	*tuns = &g_conf->tunnels;
	struct sixxsd_tunnel	*tun;
	struct sixxsd_subnets	*subs;
	struct sixxsd_subnet	*sub;

	f = fopen("sixxsd.conf.new", "w+");

	fprintf(f, "# SixXS PoP dump stored by SixXSd\n");
	fprintf(f, "\n");
	fprintf(f, "pop\n");
	fprintf(f, "\tset name %s\n", g_conf->pop_name);
	fprintf(f, "\tset ipv4 %s\n", g_conf->pop_ipv4_asc);
	fprintf(f, "\tset ipv6 %s\n", g_conf->pop_ipv6_asc);
	fprintf(f, "\n");

	/* Tunnel prefixes */
	fprintf(f, "\ttunnelprefix add %s:/48\n", g_conf->tunnels.prefix_asc);
	fprintf(f, "\n");

	/* Subnet prefixes */
	fprintf(f, "\tsubnetprefix\n");

	for (i = 0; i <= g_conf->subnets_hi; i++)
	{
		subs = &g_conf->subnets[i];
		fprintf(f, "\t\tadd %s%s::/%u\n", subs->prefix_asc, subs->prefix_length == 40 ? "00" : "", subs->prefix_length);
	}

	fprintf(f, "\tend\n");
	fprintf(f, "\n");

	/* ACLs */
	fprintf(f, "\tcliacl\n");

	for (i = 0; i < lengthof(g_conf->cli_acl); i++)
	{
		if (ipaddress_is_unspecified(&g_conf->cli_acl[i])) continue;

		inet_ntopA(&g_conf->cli_acl[i], buf, sizeof(buf));
		fprintf(f, "\t\tadd %s\n", buf);
	}

	fprintf(f, "\tend\n");
	fprintf(f, "end\n");
	fprintf(f, "\n");

	fprintf(f, "tunnel\n");
	fprintf(f, "\tset\n");

	for (i = 0; i <= tuns->tunnel_hi; i++)
	{
		tun = &tuns->tunnel[i];
		if (tun->state == SIXXSD_TSTATE_NONE) continue;

		inet_ntopA(&tun->ip_them, buf, sizeof(buf));

		if (tun->type == SIXXSD_TTYPE_PROTO41) pw = "";
		else pw = (const char *)tun->hb_password;

		fprintf(f, "\t\tconfig %x T%u %s %s %u%s%s\n",
			i,
			tun->tunnel_id,
			tun->type == SIXXSD_TTYPE_PROTO41 ? buf : tunnel_type_name(tun->type),
			tun->state == SIXXSD_TSTATE_DISABLED ? tunnel_state_name(tun->state) : tunnel_state_name(SIXXSD_TSTATE_UP),
			tun->mtu,
			tun->type == SIXXSD_TTYPE_PROTO41 ? "" : " ",
			pw);
	}

	fprintf(f, "\tend\n");
	fprintf(f, "end\n");
	fprintf(f, "\n");

	fprintf(f, "subnet\n");
	fprintf(f, "\tset\n");

	for (i = 0; i <= g_conf->subnets_hi; i++)
	{
		subs = &g_conf->subnets[i];

		for (j = 0; j < lengthof(subs->subnet); j++)
		{
			sub = &subs->subnet[j];
			if (sub->tunnel_id == SIXXSD_TUNNEL_NONE) continue;

			fprintf(f, "\t\tconfig %s%s%02x%s::/%u %x static\n",
				subs->prefix_asc,
				subs->prefix_length == 40 ? "" : "::",
				j,
				subs->prefix_length == 40 ? "" : "00",
				subs->prefix_length == 40 ? 48 : 56, sub->tunnel_id);
		}
	}

	fprintf(f, "\tend\n");
	fprintf(f, "end\n");

	fclose(f);

	/* Replace the old config with the new one */
	rename("sixxsd.conf", "sixxsd.conf.old");
	rename("sixxsd.conf.new", "sixxsd.conf");

	ctx_printf(ctx, "Configuration stored to disk\n");

	return 200;
}

static int pop_cmd_shutdown(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[]);
static int pop_cmd_shutdown(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[])
{
	ctx_printf(ctx, "Tschau, shutting down\n");
	mdolog(LOG_INFO, "Shutdown ordered\n");
	g_conf->running = false;
	return 666;
}

static int pop_cmd_set_name(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char *args[]);
static int pop_cmd_set_name(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char *args[])
{
	strncpy(g_conf->pop_name, args[0], sizeof(g_conf->pop_name));
	ctx_printf(ctx, "Name updated\n");
	return 200;
}

static int pop_cmd_get_name(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[]);
static int pop_cmd_get_name(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[])
{
	ctx_printf(ctx, "%s\n", g_conf->pop_name);
	return 200;
}

static int pop_cmd_set_ipv4(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char *args[]);
static int pop_cmd_set_ipv4(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char *args[])
{
	if (!inet_ptonA(args[0], &g_conf->pop_ipv4, NULL))
	{
		ctx_printf(ctx, "Invalid IPv4 address %s\n", args[0]);
		return 400;
	}

	/* Pre-generate a human-readable version */
	inet_ntopA(&g_conf->pop_ipv4, g_conf->pop_ipv4_asc, sizeof(g_conf->pop_ipv4_asc));

	ctx_printf(ctx, "IPv4 address updated\n");
	return 200;
}

static int pop_cmd_set_ipv6(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char *args[]);
static int pop_cmd_set_ipv6(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char *args[])
{
	if (!inet_ptonA(args[0], &g_conf->pop_ipv6, NULL))
	{
		ctx_printf(ctx, "Invalid IPv6 address %s\n", args[0]);
		return 400;
	}

	/* Pre-generate a human-readable version */
	inet_ntopA(&g_conf->pop_ipv6, g_conf->pop_ipv6_asc, sizeof(g_conf->pop_ipv6_asc));

	ctx_printf(ctx, "IPv6 address updated\n");
	return 200;
}

static int pop_cmd_tunnelprefix_list(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[]);
static int pop_cmd_tunnelprefix_list(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[])
{
	struct sixxsd_tunnels	*tuns = &g_conf->tunnels;

	if (ipaddress_is_unspecified(&tuns->prefix))
	{
		ctx_printf(ctx, "Tunnel Prefix is not configured yet\n");
		return 404;
	}

	ctx_printf(ctx, "%s:/48\n", tuns->prefix_asc);

	return 200;
}

static int pop_cmd_tunnelprefix_add(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char *args[]);
static int pop_cmd_tunnelprefix_add(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char *args[])
{
	IPADDRESS		ip;
	unsigned int		j;
	struct sixxsd_tunnels	*tuns = &g_conf->tunnels;

	if (!inet_ptonA(args[0], &ip, NULL))
	{
		ctx_printf(ctx, "Invalid IPv6 prefix %s\n", args[0]);
		return 400;
	}

	if (!ipaddress_is_unspecified(&tuns->prefix))
	{
		ctx_printf(ctx, "Tunnel Prefix already configured\n");
		return 200;
	}

	/* Fill in the prefix */
	memcpy(&tuns->prefix, &ip, sizeof(tuns->prefix));

	/* Pre-generate a human-readable version */
	inet_ntopA(&tuns->prefix, tuns->prefix_asc, sizeof(tuns->prefix_asc));

	/* Reduce the double :: to a single : as then we can just append the tunnel postfix */
	j = strlen(tuns->prefix_asc);
	if (j < 8)
	{
		ctx_printf(ctx, "Tunnel Prefix had less than 8 chars!? (%s)\n", tuns->prefix_asc);
		return 500;
	}

	tuns->prefix_asc[j-1] = '\0';

	/* Bring them up if possible */
	iface_upnets();

	ctx_printf(ctx, "Tunnel Prefix %s added\n", tuns->prefix_asc);
	return 200;
}

static int pop_cmd_subnetprefix_list(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[]);
static int pop_cmd_subnetprefix_list(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[])
{
	struct sixxsd_subnets	*subs;
	unsigned int		i;

	for (i = 0; i <= g_conf->subnets_hi; i++)
	{
		subs = &g_conf->subnets[i];

		ctx_printf(ctx, "%s%s::/%u\n", subs->prefix_asc, subs->prefix_length == 40 ? "00" : "", subs->prefix_length);
	}

	return 200;
}

static int pop_cmd_subnetprefix_add(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char *args[]);
static int pop_cmd_subnetprefix_add(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char *args[])
{
	IPADDRESS		ip;
	unsigned int		i, j, prefixlen, rembytes;
	struct sixxsd_subnets	*subs;
	const char		*remstring;

	if (!inet_ptonA(args[0], &ip, &prefixlen))
	{
		ctx_printf(ctx, "Invalid IPv6 prefix %s\n", args[0]);
		return 400;
	}

	if (prefixlen != 48 && prefixlen != 40)
	{
		ctx_printf(ctx, "A Prefixlength %u not accepted (only /48's for /56 subnets or a /40 for /48 subnets)\n", prefixlen);
		return 400;
	}

	/* Find old one */
	for (i = 0; i < lengthof(g_conf->subnets); i++)
	{
		subs = &g_conf->subnets[i];
		if (memcmp(&subs->prefix, &ip, sizeof(ip)) != 0 || subs->prefix_length != prefixlen) continue;

		ctx_printf(ctx, "Subnet Prefix already configured\n");
		return 200;
	}

	/* Find an empty slot and add it */
	for (i = 0; i < lengthof(g_conf->subnets); i++)
	{
		subs = &g_conf->subnets[i];

		if (!ipaddress_is_unspecified(&subs->prefix)) continue;

		memcpy(&subs->prefix, &ip, sizeof(subs->prefix));
		subs->prefix_length = prefixlen;

		/* Pre-generate a human-readable version */
		inet_ntopA(&subs->prefix, subs->prefix_asc, sizeof(subs->prefix_asc));

		/* Did it output anything? */
		j = strlen(subs->prefix_asc);
		if (j < 6)
		{
			ctx_printf(ctx, "Subnet Prefix had less than 6 chars!? (%s)\n", subs->prefix_asc);
			return 500;
		}

		if (prefixlen == 40)
		{
			rembytes = 4;
			remstring = "00::";
		}
		else
		{
			rembytes = 2;
			remstring = "::";
		}

		/* Remove the "00::" from the /40 as then we can just append the subnet postfix */
		/* Remove the   "::" from the /48 ... */
		if (strcmp(&subs->prefix_asc[j - rembytes], remstring) != 0)
		{
			assert(false);
			ctx_printf(ctx, "Can't handle a subnet prefix which does not end in %s, got %s\n", remstring, subs->prefix_asc);
			return 500;
		}

		/* Remove 00:: */
		subs->prefix_asc[j - rembytes] = '\0';

		/* The new high one */
		g_conf->subnets_hi = i;

		/* Bring them up if possible */
		iface_upnets();

		ctx_printf(ctx, "Subnet Prefix %s00::/%u added\n", subs->prefix_asc, subs->prefix_length);
		return 200;
	}

	ctx_printf(ctx, "No more available empty subnet prefixes, this requires a recompile\n");
	return 400;
}

static int pop_cmd_cliacl_list(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[]);
static int pop_cmd_cliacl_list(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[])
{
	char		hst[NI_MAXHOST];
	unsigned int	i, count = 0;

	for (i = 0; i < lengthof(g_conf->cli_acl); i++)
	{
		if (ipaddress_is_unspecified(&g_conf->cli_acl[i])) continue;

		inet_ntopA(&g_conf->cli_acl[i], hst, sizeof(hst));
		ctx_printf(ctx, "%s\n", hst);
		count++;
	}

	if (count == 0)
	{
		ctx_printf(ctx, "No CLI ACLs are configured\n");
		return 404;
	}

	return 200;
}

static int pop_cmd_cliacl_add(struct sixxsd_context *ctx, const unsigned int argc, const char *args[]);
static int pop_cmd_cliacl_add(struct sixxsd_context *ctx, const unsigned int argc, const char *args[])
{
	IPADDRESS		ip;
	unsigned int		i;

	if (!inet_ptonA(args[0], &ip, NULL))
	{
		ctx_printf(ctx, "Invalid IP address %s\n", args[0]);
		return 400;
	}

	/* Find old one */
	for (i = 0; i < lengthof(g_conf->cli_acl); i++)
	{
		if (memcmp(&g_conf->cli_acl[i], &ip, sizeof(ip)) != 0) continue;

		if (argc == 2)
		{
			memzero(&g_conf->cli_acl[i], sizeof(g_conf->cli_acl[i]));
			ctx_printf(ctx, "CLI ACL removed\n");
			return 200;
		}

		ctx_printf(ctx, "CLI ACL already present\n");
		return 200;
	}
	
	/* Find empty slot and add it */
	for (i = 0; i < lengthof(g_conf->cli_acl); i++)
	{
		if (!ipaddress_is_unspecified(&g_conf->cli_acl[i])) continue;

		memcpy(&g_conf->cli_acl[i], &ip, sizeof(g_conf->cli_acl[i]));

		ctx_printf(ctx, "CLI ACL added\n");
		return 200;
	}

	ctx_printf(ctx, "No more available empty CLI ACL slots!!!\n");
	return 400;
}

struct ctx_menu ctx_menu_pop_set[] =
{
	{"set",			NULL,				0,0,	NULL,			NULL },
	{"debug",		pop_cmd_set_debug,		2,2,	"<section> {on|off}",	"Enable or disable output from a program section" },
	{"ipv4",		pop_cmd_set_ipv4,		1,1,	"<ipv4",		"Set PoP IPv4" },
	{"ipv6",		pop_cmd_set_ipv6,		1,1,	"<ipv6>",		"Set PoP IPv6" },
	{"name",		pop_cmd_set_name,		1,1,	"<name>",		"Set PoP name" },
	{"verbosity",		pop_cmd_set_verbosity,		1,1,	"<level>",		"Change verbosity level" },

	{NULL,			NULL,				0,0,	NULL,			NULL },
};

struct ctx_menu ctx_menu_pop_get[] =
{
	{"get",			NULL,				0,0,	NULL,			NULL },
	{"name",		pop_cmd_get_name,		0,0,	NULL,			"Get PoP name" },
	{NULL,			NULL,				0,0,	NULL,			NULL },
};

struct ctx_menu ctx_menu_pop_show[] =
{
	{"show",	NULL,				0,0,	NULL,		NULL },
	{"info",	pop_cmd_show_info,		0,0,	NULL,		"Show information" },
	{"hostinfo",	pop_cmd_show_hostinfo,		0,0,	NULL,		"Show host information" },
	{"status",	pop_cmd_show_status,		0,0,	NULL,		"Show status" },
	{"threads",	thread_list,			0,0,	NULL,		"Show running threads" },
	{"timeinfo",	pop_cmd_show_timeinfo,		0,0,	NULL,		"Show time information" },
	{"unixtime",	pop_cmd_show_unixtime,		0,0,	NULL,		"Show UNIX timestamp" },
	{"uptime",	pop_cmd_show_uptime,		0,0,	NULL,		"Show uptime of the PoP" },
	{"version",	pop_cmd_show_version,		0,0,	NULL,		"Show version information" },
	{NULL,		NULL,				0,0,	NULL,		NULL },
};

struct ctx_menu ctx_menu_pop_cliacl[] =
{
	{"show",	NULL,				0,0,	NULL,		NULL },
	{"add",		pop_cmd_cliacl_add,		1,1,	"<prefix>",	"Add/Refresh Cli ACL" },
	{"list",	pop_cmd_cliacl_list,		0,0,	NULL,		"List configured CLI ACLs" },
	{NULL,		NULL,				0,0,	NULL,		NULL },
};

struct ctx_menu ctx_menu_pop_tunnelprefix[] =
{
	{"show",	NULL,				0,0,	NULL,		NULL },
	{"add",		pop_cmd_tunnelprefix_add,	1,1,	"<prefix>",	"Add/Refresh Tunnel Prefix" },
	{"list",	pop_cmd_tunnelprefix_list,	0,0,	NULL,		"List configured Tunnel Prefixes" },
	{NULL,		NULL,				0,0,	NULL,		NULL },
};

struct ctx_menu ctx_menu_pop_subnetprefix[] =
{
	{"show",	NULL,				0,0,	NULL,		NULL },
	{"add",		pop_cmd_subnetprefix_add,	1,1,	"<prefix>",	"Add/Refresh Subnet Prefix" },
	{"list",	pop_cmd_subnetprefix_list,	0,0,	NULL,		"List configured Subnet Prefixes" },
	{NULL,		NULL,				0,0,	NULL,		NULL },
};

CONTEXT_MENU(pop_cliacl)
CONTEXT_CMD(pop_cliacl)
CONTEXT_MENU(pop_get)
CONTEXT_CMD(pop_get)
CONTEXT_MENU(pop_set)
CONTEXT_CMD(pop_set)
CONTEXT_MENU(pop_show)
CONTEXT_CMD(pop_show)
CONTEXT_MENU(pop_tunnelprefix)
CONTEXT_CMD(pop_tunnelprefix)
CONTEXT_MENU(pop_subnetprefix)
CONTEXT_CMD(pop_subnetprefix)

struct ctx_menu ctx_menu_pop[] =
{
	{"pop",		NULL,				0,0,	NULL,		NULL },
	{"cliacl",	ctx_cmd_pop_cliacl,		0,-1,	CONTEXT_SUB,	"Manage CLI ACLs" },
	{"get",		ctx_cmd_pop_get,		0,-1,	CONTEXT_SUB,	"Get configuration Information" },
	{"set",		ctx_cmd_pop_set,		0,-1,	CONTEXT_SUB,	"Configure the PoP" },
	{"saveconfig",	pop_cmd_saveconfig,		0,0,	NULL,		"Save the configuration to disk" },
	{"show",	ctx_cmd_pop_show,		0,-1,	CONTEXT_SUB,	"Show how the PoP is configured" },
	{"shutdown",	pop_cmd_shutdown,		0,-1,	NULL,		"Shutdown" },
	{"subnetprefix",ctx_cmd_pop_subnetprefix,	0,-1,	CONTEXT_SUB,	"Manage subnetprefixes" },
	{"tunnelprefix",ctx_cmd_pop_tunnelprefix,	0,-1,	CONTEXT_SUB,	"Manage tunnelprefixes" },
	{NULL,		NULL,				0,0,	NULL,		NULL },
};

CONTEXT_CMD(pop)

