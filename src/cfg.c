/**************************************
 SixXSd - SixXS PoP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
***************************************
 $Author: jeroen $
 $Id: cfg.c,v 1.12 2006-03-01 09:31:04 jeroen Exp $
 $Date: 2006-03-01 09:31:04 $

 SixXSd Configuration Handler
**************************************/

#include "sixxsd.h"

const char module_cfg[] = "cfg";
#define module module_cfg

#define CFG_PORT "42003"

/* Client */
struct cfg_client
{
	char		clienthost[NI_MAXHOST];
	char		clientservice[NI_MAXSERV];
	char		__pad[3];
	SOCKET		socket;				/* Remote */
};

void cfg_log(int level, const char *fmt, ...);
void cfg_log(int level, const char *fmt, ...)
{
	char	buf[1024];
	va_list	ap;
	
	/* Print the host+port this is coming from */
	snprintf(buf, sizeof(buf), "(0x%x) : ", (unsigned int)OS_GetThisThreadId());

	/* Print the log message behind it */
	va_start(ap, fmt);
	vsnprintf(buf+strlen(buf), sizeof(buf)-strlen(buf), fmt, ap);
	va_end(ap);
	
	/* Actually Log it */
	mdolog(level, buf);
}

/********************************************************************
  PoP Commands
********************************************************************/
bool cfg_cmd_pop(int sock, const char UNUSED *args);
bool cfg_cmd_pop(int sock, const char UNUSED *args)
{
	sock_printf(sock, "+OK PoP Configuration accepted\n");
	return true;
}

bool cfg_cmd_pop_name(int sock, const char *args);
bool cfg_cmd_pop_name(int sock, const char *args)
{
	if (g_conf->pop_name) free(g_conf->pop_name);
	g_conf->pop_name = strdup(args);
	sock_printf(sock, "+OK Accepted PoP Name\n");
	return true;
}

bool cfg_cmd_pop_ipv4(int sock, const char *args);
bool cfg_cmd_pop_ipv4(int sock, const char *args)
{
	if (!inet_pton(AF_INET, args, &g_conf->pop_ipv4))
	{
		sock_printf(sock, "-ERR argument (%s) didn't specify a valid IPv4 address\n", args);
		return false;
	}
	sock_printf(sock, "+OK PoP now has IPv4 address %s\n", args);
	return true;
}

bool cfg_cmd_pop_ipv6(int sock, const char *args);
bool cfg_cmd_pop_ipv6(int sock, const char *args)
{
	if (!inet_pton(AF_INET6, args, &g_conf->pop_ipv6))
	{
		sock_printf(sock, "-ERR argument (%s) didn't specify a valid IPv6 address\n", args);
		return false;
	}
	sock_printf(sock, "+OK PoP now has IPv6 address %s\n", args);
	return true;
}

bool cfg_stringtoprefix(const char *string, struct in6_addr *prefix, unsigned int *length);
bool cfg_stringtoprefix(const char *string, struct in6_addr *prefix, unsigned int *length)
{
	unsigned int	i;
	bool		ret = true;
	char		*str;

	str = strdup(string);
	if (!str) return false;

	/* Find the slash */
	for (i=0; str[i] != '\0' && str[i] != '/'; i++);
	if (str[i] == '\0')
	{
		*length = 128;
		i = 0;
	}
	else
	{
		str[i] = '\0';
		*length = atoi(&str[i+1]);
	}

	if (!inet_pton(AF_INET6, str, prefix)) ret = false;

	free(str);

	return ret;
}

bool cfg_pop_prefix_add(int sock, const char *args);
bool cfg_pop_prefix_add(int sock, const char *args)
{
	struct sixxs_pop_prefix	*pp, *pn;
	bool			found = false;

	pp = malloc(sizeof(*pp));
	if (!pp)
	{
		sock_printf(sock, "-ERR No memory for new pop prefix: %s\n", args);
		return false;
	}

	pp->next = NULL;

	if (!cfg_stringtoprefix(args, &pp->prefix, &pp->length))
	{
		sock_printf(sock, "-ERR Invalid prefix: %s\n", args);
		free(pp);
		return false;
	}

	OS_Mutex_Lock(&g_conf->mutex, "cfg_pop_prefix_add");

	/* Add it to the list of prefixes */
	for (pn = g_conf->pop_prefixes; pn; pn = pn->next)
	{
		if (	pp->length == pn->length &&
			memcmp(&pp->prefix, &pn->prefix, 16) == 0)
		{
			found = true;
			break;
		}
	}

	if (!found)
	{
		/* Prepend it to the list */
		pp->next = g_conf->pop_prefixes;
		g_conf->pop_prefixes = pp;
	}

	OS_Mutex_Release(&g_conf->mutex, "cfg_pop_prefix_add");

	sock_printf(sock, "+OK Accepted PoP Prefix %s (%s)\n", args, found ? "new" : "old");

	return true;
}

bool cfg_pop_prefix_check(struct in6_addr *prefix, unsigned int length)
{
	struct sixxs_pop_prefix *pp;
	bool			ret = false;

	OS_Mutex_Lock(&g_conf->mutex, "cfg_pop_prefix_check");

	for (pp = g_conf->pop_prefixes; pp; pp = pp->next)
	{
		if (pfx_issubnet(prefix, length, &pp->prefix, pp->length))
		{
			ret = true;
			break;
		}
	}

	OS_Mutex_Release(&g_conf->mutex, "cfg_pop_prefix_check");

	return ret;
}

bool cfg_cmd_pop_tunnelprefix(int sock, const char *args);
bool cfg_cmd_pop_tunnelprefix(int sock, const char *args)
{
	return cfg_pop_prefix_add(sock, args);
}

bool cfg_cmd_pop_subnetprefix(int sock, const char *args);
bool cfg_cmd_pop_subnetprefix(int sock, const char *args)
{
	return cfg_pop_prefix_add(sock, args);
}

bool cfg_cmd_pop_tunneldevice(int sock, const char *args);
bool cfg_cmd_pop_tunneldevice(int sock, const char *args)
{
	if (g_conf->pop_tunneldevice) free(g_conf->pop_tunneldevice);
	g_conf->pop_tunneldevice = strdup(args);
	sock_printf(sock, "+OK Accepted PoP Tunnel Device %s\n", args);
	return true;
}

bool cfg_cmd_pop_ignoredevices(int sock, const char *args);
bool cfg_cmd_pop_ignoredevices(int sock, const char *args)
{
	if (g_conf->pop_ignoredevices) free(g_conf->pop_ignoredevices);
	g_conf->pop_ignoredevices = strdup(args);
	sock_printf(sock, "+OK Accepted PoP Tunnel Device %s\n", args);
	return true;
}

bool cfg_cmd_pop_hb_supported(int sock, const char *args);
bool cfg_cmd_pop_hb_supported(int sock, const char *args)
{
	if (strcmp(args, "Y") == 0) g_conf->pop_hb_supported = true;
	else g_conf->pop_hb_supported = false;
	sock_printf(sock, "+OK PoP %s Heartbeats\n",  g_conf->pop_hb_supported ? "supports" : "doesn't support");
	return true;
}

bool cfg_cmd_pop_hb_sendinterval(int sock, const char *args);
bool cfg_cmd_pop_hb_sendinterval(int sock, const char *args)
{
	g_conf->pop_hb_sendinterval = atoi(args);
	sock_printf(sock, "+OK PoP Heartbeat Send Interval now %d\n",  g_conf->pop_hb_sendinterval);
	return true;
}

bool cfg_cmd_pop_hb_timeout(int sock, const char *args);
bool cfg_cmd_pop_hb_timeout(int sock, const char *args)
{
	g_conf->pop_hb_timeout = atoi(args);
	sock_printf(sock, "+OK PoP Heartbeat Timeout now %u\n",  g_conf->pop_hb_timeout);
	return true;
}

bool cfg_cmd_pop_tinc_supported(int sock, const char *args);
bool cfg_cmd_pop_tinc_supported(int sock, const char *args)
{
	if (strcmp(args, "Y") == 0) g_conf->pop_tinc_supported = true;
	else g_conf->pop_tinc_supported = false;
	sock_printf(sock, "+OK PoP %s tinc\n",  g_conf->pop_tinc_supported ? "supports" : "doesn't support");
	return true;
}

bool cfg_cmd_pop_tinc_device(int sock, const char *args);
bool cfg_cmd_pop_tinc_device(int sock, const char *args)
{
	if (g_conf->pop_tinc_device) free(g_conf->pop_tinc_device);
	g_conf->pop_tinc_device = strdup(args);
	sock_printf(sock, "+OK Accepted tinc Device %s\n", args);
	return true;
}

bool cfg_cmd_pop_tinc_config(int sock, const char *args);
bool cfg_cmd_pop_tinc_config(int sock, const char *args)
{
	if (g_conf->pop_tinc_config) free(g_conf->pop_tinc_config);
	g_conf->pop_tinc_config = strdup(args);
	sock_printf(sock, "+OK Accepted tinc config %s\n", args);
	return true;
}

/*
 * TUNNEL
 * "tunnel <devicenumber> <ipv6_us> <ipv6_them> <ipv6_prefixlen> <ipv4_us> <ipv4_them|heartbeat|tinc|ayiya> <up|disabled|down> <mtu> [<heartbeatpassword>]"
 * Note: ipv4_us is ignored, should be the same everywhere
 */
bool cfg_cmd_tunnel(int sock, const char *args);
bool cfg_cmd_tunnel(int sock, const char *args)
{
	unsigned int		fields = countfields(args);
	char			buf[1024];
	struct in6_addr		ipv6_us, ipv6_them;
	struct in_addr		ipv4_them;
	int			id, prefixlen, mtu;
	enum iface_type		type = IFACE_UNSPEC;
	enum iface_state	state = IFSTATE_DISABLED;
	
	if (fields != 8 && fields != 9)
	{
		sock_printf(sock, "-ERR tunnel requires 8 or 9 arguments, got %u : '%s'\n", fields, args);
		return true;
	}

	/* Get the devicenumber */
	if (!copyfield(args, 1, buf, sizeof(buf)))
	{
		sock_printf(sock, "-ERR Field 1 didn't exist in '%s'\n", args);
		return false;
	}
	id = strtol(buf, (char **)NULL, 10);
	if (id == 0)
	{
		sock_printf(sock, "-ERR Invalid interface number '%s'\n", buf);
		return false;
	}

	/* Get the ipv6_us address */
	if (!copyfield(args, 2, buf, sizeof(buf)))
	{
		sock_printf(sock, "-ERR Field 2 didn't exist in '%s'\n", args);
		return false;
	}
	if (!inet_pton(AF_INET6, buf, &ipv6_us))
	{
		sock_printf(sock, "-ERR Invalid IPv6_us address '%s'\n", buf);
		return false;
	}

	/* Get the ipv6_them address */
	if (!copyfield(args, 3, buf, sizeof(buf)))
	{
		sock_printf(sock, "-ERR Field 3 didn't exist in '%s'\n", args);
		return false;
	}
	if (!inet_pton(AF_INET6, buf, &ipv6_them))
	{
		sock_printf(sock, "-ERR Invalid IPv6_them address '%s'\n", buf);
		return false;
	}

	/* Get the prefixlen */
	if (!copyfield(args, 4, buf, sizeof(buf)))
	{
		sock_printf(sock, "-ERR Field 4 didn't exist in '%s'\n", args);
		return false;
	}
	prefixlen = atoi(buf);

	/* Get the ipv4_them address */
	memset(&ipv4_them, 0, sizeof(ipv4_them));
	if (!copyfield(args, 6, buf, sizeof(buf)))
	{
		sock_printf(sock, "-ERR Field 6 didn't exist in '%s'\n", args);
		return false;
	}
	if (strcasecmp(buf, "heartbeat") == 0) type = IFACE_PROTO41_HB;
	else if (strcasecmp(buf, "tinc") == 0) type = IFACE_TINC;
	else if (strcasecmp(buf, "ayiya") == 0) type = IFACE_AYIYA;
	else if (inet_pton(AF_INET, buf, &ipv4_them)) type = IFACE_PROTO41;
	else
	{
		sock_printf(sock, "-ERR Unknown value for IPv4_them '%s'\n", buf);
		return false;
	}

	/* Get the interface state */
	if (!copyfield(args, 7, buf, sizeof(buf)))
	{
		sock_printf(sock, "-ERR Field 7 didn't exist in '%s'\n", args);
		return false;
	}
	if (strcmp(buf, "up") == 0)
	{
		/*
		 * Dynamic tunnels start in down state
		 * and are marked up on the first receival
		 * of a Heartbeat packet, thus client initiated
		 */
		if (	type == IFACE_PROTO41_HB ||
			type == IFACE_AYIYA)
		{
			state = IFSTATE_DOWN;
		}
		else state = IFSTATE_UP;
	}
	else if (strcmp(buf, "down") == 0) state = IFSTATE_DOWN;
	else if (strcmp(buf, "disabled") == 0) state = IFSTATE_DISABLED;
	else
	{
		sock_printf(sock, "-ERR Unknown interface state '%s'\n", buf);
		return false;
	}

	/* MTU size */
	if (!copyfield(args, 8, buf, sizeof(buf)))
	{
		sock_printf(sock, "-ERR Field 8 didn't exist in '%s'\n", args);
		return false;
	}
	mtu = atoi(buf);

	/* Get the password (if it exists) */
	if (fields == 9)
	{
		if (!copyfield(args, 9, buf, sizeof(buf)))
		{
			sock_printf(sock, "-ERR Field 9 didn't exist in '%s'\n", args);
			return false;
		}
	}

	int_reconfig(id, &ipv6_us, &ipv6_them, prefixlen, ipv4_them, type, state, mtu, fields == 9 ? buf : NULL);

	sock_printf(sock, "+OK Tunnel %u accepted\n", id);
	return true;
}

/*
 * ROUTE
 * "route <prefix>/<prefixlen> <nexthop> <up|disabled|down> <static|bgp>"
 */
bool cfg_cmd_route(int sock, const char *args);
bool cfg_cmd_route(int sock, const char *args)
{
	char			buf[1024], pfix[64];
	unsigned int		fields = countfields(args), length = 128;
	bool			enabled = false, ignore = false;
	struct in6_addr		prefix, nexthop;
	struct sixxs_prefix	*pfx;
	struct sixxs_interface	*iface;

	if (fields != 4)
	{
		sock_printf(sock, "-ERR route requires 4 arguments, got %u : '%s'\n", fields, args);
		return true;
	}

	/* Get the prefix */
	if (!copyfield(args, 1, pfix, sizeof(pfix)))
	{
		sock_printf(sock, "-ERR Field 1 of route didn't exist in '%s'\n", args);
		return false;
	}

	if (!copyfield(args, 3, buf, sizeof(buf)))
	{
		sock_printf(sock, "-ERR Field 3 of route didn't exist in '%s'\n", args);
		return false;
	}
	if (strcmp(buf, "up") == 0) enabled = true;
	else if (strcmp(buf, "down") == 0) enabled = false;
	else
	{
		/* Ignore disabled devices */
		sock_printf(sock, "+OK Ignoring disabled route %s\n", pfix);
		return true;
	}

	if (!copyfield(args, 4, buf, sizeof(buf)))
	{
		sock_printf(sock, "-ERR Field 4 didn't exist in '%s'\n", args);
		return false;
	}
	if (strcmp(buf, "static") == 0) ignore = false;
	else if (strcmp(buf, "bgp") == 0) ignore = true;
	else
	{
		/* Ignore disabled devices */
		sock_printf(sock, "-ERR Unknown Route Type %s for %s\n", buf, pfix);
		return false;
	}

	if (!cfg_stringtoprefix(pfix, &prefix, &length))
	{
		sock_printf(sock, "-ERR Invalid prefix address '%s'\n", pfix);
		return false;
	}

	if (!copyfield(args, 2, buf, sizeof(buf)))
	{
		sock_printf(sock, "-ERR Field 2 of route didn't exist in '%s'\n", args);
		return false;
	}
	if (!inet_pton(AF_INET6, buf, &nexthop))
	{
		sock_printf(sock, "-ERR Invalid nexthop address '%s' for route %s\n", buf, pfix);
		return false;
	}

	/* Lookup which interface it belongs to */
	pfx = pfx_get(&nexthop, 128);
	if (!pfx)
	{
		sock_printf(sock, "-ERR Couldn't find nexthop '%s' while determining interface_id for route %s\n", buf, pfix);
		return false;
	}

	iface = int_get(pfx->interface_id);
	if (!iface)
	{
		sock_printf(sock, "-ERR Couldn't find interface %u for route %s\n", pfx->interface_id, pfix);
		OS_Mutex_Release(&pfx->mutex, "cfg_cmd_route");
		return false;
	}

	/* Add the route */
	pfx_reconfig(&prefix, length, &nexthop, enabled, ignore, false, iface);

	sock_printf(sock, "+OK Route %s accepted over interface %s/%u\n",
		pfix, iface->name, pfx->interface_id);

	OS_Mutex_Release(&iface->mutex, "cfg_cmd_route");
	OS_Mutex_Release(&pfx->mutex, "cfg_cmd_route");
	return true;
}

/* MISC */
bool cfg_cmd_help(int sock, const char *args);
/* Defined after cfg_cmds */

bool cfg_cmd_reply(int sock, const char *args);
bool cfg_cmd_reply(int sock, const char *args)
{
	sock_printf(sock, "+OK You mentioned: %s\n", args);
	return true;
}

bool cfg_cmd_status(int sock, const char UNUSED *args);
bool cfg_cmd_status(int sock, const char UNUSED *args)
{
	struct sixxs_thread 	*t = NULL;
	os_thread		thread = OS_GetThisThread();
	unsigned int		i;
	struct sixxs_interface	*iface = NULL;
	struct sixxs_prefix	*pfx = NULL;
	char			buf1[1024], buf2[1024];
	bool			all = false, inactive = false, ok = false;
	struct tm		teem;
	time_t			now = time(NULL);

	now = mktime(gmtime_r(&now, &teem));

	if (args[0] == '\0') all = true;
	else if (strcasecmp(args, "all") == 0) all = inactive = true;

	sock_printf(sock, "+OK Status coming up...\n");

	if (all || strcasecmp(args, "threads") == 0)
	{
		ok = true;
		sock_printf(sock, "Threads:\n");
		for (t = g_conf->threads; t; t = t->next)
		{
			sock_printf(sock, "Thread 0x%x : %s%s\n",
				(void *)t->thread, t->description,
				OS_Thread_Equal(t->thread, thread) ? " (this)" : "");
		}
		sock_printf(sock, "\n");
	}

	if (!all && strncasecmp(args, "interface ", 10) == 0)
	{
		ok = true;
		i = atoi(&args[10]);
		iface = int_get(i);
		if (iface)
		{
			sock_printf(sock, "Interface %u\n", iface->interface_id);
			sock_printf(sock, "\n");
			sock_printf(sock, "Name                  : %s\n", iface->name);
			sock_printf(sock, "Kernel Interface Index: %u\n", iface->kernel_ifindex);
			sock_printf(sock, "Kernel Interface Flags: 0x%x\n", iface->kernel_flags);
			sock_printf(sock, "\n");

			memset(buf1, 0, sizeof(buf1));
			inet_ntop(AF_INET6, &iface->ipv6_us, buf1, sizeof(buf1));
			sock_printf(sock, "IPv6 Us               : %s/%u\n", buf1, iface->prefixlen);

			memset(buf1, 0, sizeof(buf1));
			inet_ntop(AF_INET6, &iface->ipv6_them, buf1, sizeof(buf1));
			sock_printf(sock, "IPv6 Them             : %s/%u\n", buf1, iface->prefixlen);

			memset(buf1, 0, sizeof(buf1));
			inet_ntop(AF_INET, &iface->ipv4_them, buf1, sizeof(buf1));
		
			switch (iface->type)
			{
			case IFACE_IGNORE:
				sock_printf(sock, "Type                  : ignore\n");
				break;
			case IFACE_PROTO41:
				sock_printf(sock, "Type                  : proto-41\n");
				sock_printf(sock, "Endpoint              : %s\n", buf1);
				break;
			case IFACE_PROTO41_HB:
				sock_printf(sock, "Type                  : proto-41_hb\n");
				sock_printf(sock, "Endpoint              : %s\n", buf1);
				sock_printf(sock, "Password              : %s\n", iface->password);
				gmtime_r(&iface->hb_lastbeat, &teem);
				strftime(buf1, sizeof(buf1), "%Y-%m-%d %H:%M:%S", &teem);
				sock_printf(sock, "Last Beat             : %s (%u seconds ago)\n", buf1,
										(now - iface->hb_lastbeat));
				break;
			case IFACE_AYIYA:
				sock_printf(sock, "Type                  : ayiya\n");
				sock_printf(sock, "Endpoint              : %s\n", buf1);
				sock_printf(sock, "Client Port           : %u\n", iface->ayiya_port);
				sock_printf(sock, "Server Port           : %u\n", iface->ayiya_sport);
				sock_printf(sock, "Protocol              : %s\n",
					iface->ayiya_protocol == 0		? "unused" :
					iface->ayiya_protocol == IPPROTO_UDP	? "udp" :
					iface->ayiya_protocol == IPPROTO_TCP	? "tcp"
										: "unknown");
				sock_printf(sock, "Password              : %s\n", iface->password);
				gmtime_r(&iface->hb_lastbeat, &teem);
				strftime(buf1, sizeof(buf1), "%Y-%m-%d %H:%M:%S", &teem);
				sock_printf(sock, "Last Beat             : %s (%u seconds ago)\n", buf1,
										(now - iface->hb_lastbeat));
				break;
			case IFACE_TINC:
				sock_printf(sock, "Type                  : tinc\n");
				break;
			default:
				sock_printf(sock, "unknown - WARNING!!!\n");
			}

			if (iface->lastalive != 0)
			{
				gmtime_r(&iface->lastalive, &teem);
				strftime(buf1, sizeof(buf1), "%Y-%m-%d %H:%M:%S", &teem);
				sock_printf(sock, "Last Alive            : %s (%u seconds ago)\n", buf1, (now - iface->lastalive));
			}
			else sock_printf(sock, "Last Alive            : never\n");

			if (iface->prevdead != 0)
			{
				gmtime_r(&iface->prevdead, &teem);
				strftime(buf1, sizeof(buf1), "%Y-%m-%d %H:%M:%S", &teem);
				sock_printf(sock, "Previously Dead       : %s (%u seconds ago)\n", buf1, (now - iface->prevdead));
			}
			else sock_printf(sock, "Previously Dead       : never\n");

			sock_printf(sock, "\n");
			sock_printf(sock, "State                 : %s\n",
				iface->state == IFSTATE_DISABLED	? "disabled" :
				iface->state == IFSTATE_UP		? "up" :
				iface->state == IFSTATE_DOWN		? "down"
									: "!unknown!");
			sock_printf(sock, "Synced                : %s %s %s %s %s\n",
				iface->synced_link	? "LINK"	: "link",
				iface->synced_addr	? "ADDRESS"	: "address",
				iface->synced_local	? "LOCAL"	: "local",
				iface->synced_remote	? "REMOTE"	: "remote",
				iface->synced_subnet	? "SUBNET"	: "subnet",
				buf2);

			sock_printf(sock, "\n");
			sock_printf(sock, "Latency               : %.2f\n", iface->latency);
			sock_printf(sock, "Loss                  : %2.2f\n", iface->loss);
			sock_printf(sock, "Octets (in)           : %llu\n", iface->inoct);
			sock_printf(sock, "Octets (out)          : %llu\n", iface->outoct);
			sock_printf(sock, "Packets (in)          : %llu\n", iface->inpkt);
			sock_printf(sock, "Packets (out)         : %llu\n", iface->outpkt);
			OS_Mutex_Release(&iface->mutex, "cfg_cmd_status");
		}
		else
		{
			sock_printf(sock, "No interface %u\n");
		}
	}

	if (all || strcasecmp(args, "interfaces") == 0)
	{
		ok = true;
		sock_printf(sock, "Interfaces:\n");
		/* Walk through all the interfaces */
		OS_Mutex_Lock(&g_conf->mutex, "cfg_cmd_status");
		for (i = 0; i < g_conf->max_interfaces; i++)
		{
			iface = g_conf->interfaces + i;
			if (	iface->type == IFACE_UNSPEC ||
				(iface->state == IFSTATE_DISABLED && !inactive))
			{
				continue;
			}

			memset(buf1, 0, sizeof(buf1));
			inet_ntop(AF_INET, &iface->ipv4_them, buf1, sizeof(buf1));
		
			switch (iface->type)
			{
			case IFACE_IGNORE:
				snprintf(buf2, sizeof(buf2), "ignore");
				break;
			case IFACE_PROTO41:
				snprintf(buf2, sizeof(buf2), "proto41 %s", buf1);
				break;
			case IFACE_PROTO41_HB:
				snprintf(buf2, sizeof(buf2), "proto41_hb %s %s", buf1, iface->password);
				break;
			case IFACE_TINC:
				snprintf(buf2, sizeof(buf2), "tinc");
				break;
			case IFACE_AYIYA:
				snprintf(buf2, sizeof(buf2), "ayiya %s %s %u %u %s",
					buf1,
					iface->password,
					iface->ayiya_port,
					iface->ayiya_sport,
					iface->ayiya_protocol == 0		? "unused" :
					iface->ayiya_protocol == IPPROTO_UDP	? "udp" :
					iface->ayiya_protocol == IPPROTO_TCP	? "tcp"
										: "unknown");
				break;
			default:
				snprintf(buf2, sizeof(buf2), "unknown - WARNING!");
			}

			sock_printf(sock, "%s %u %s %lld %lld %lld %lld %s%s%s%s%s %s\n",
				iface->name, i,
				iface->state == IFSTATE_DISABLED	? "disabled" :
				iface->state == IFSTATE_UP		? "up" :
				iface->state == IFSTATE_DOWN		? "down"
									: "!unknown!",
				iface->inoct, iface->outoct,
				iface->inpkt, iface->outpkt,
				iface->synced_link ? "I" : "i",
				iface->synced_addr ? "A" : "a",
				iface->synced_local ? "L" : "l",
				iface->synced_remote ? "R" : "r",
				iface->synced_subnet ? "S" : "s",
				buf2);
		}
		OS_Mutex_Release(&g_conf->mutex, "cfg_cmd_status");
		sock_printf(sock, "\n");
	}

	if (all || strcasecmp(args, "routes") == 0)
	{
		ok = true;
		sock_printf(sock, "Routes:\n");
		/* Walk through all the routes */
		OS_Mutex_Lock(&g_conf->mutex, "cfg_cmd_status");
		for (i = 0; i < g_conf->max_prefixes; i++)
		{
			pfx = g_conf->prefixes + i;
			if (!pfx->valid || pfx->length == 128) continue;

			memset(buf1, 0, sizeof(buf1));
			inet_ntop(AF_INET6, &pfx->prefix, buf1, sizeof(buf1));

			memset(buf2, 0, sizeof(buf2));
			inet_ntop(AF_INET6, &pfx->nexthop, buf2, sizeof(buf2));
		
			OS_Mutex_Release(&g_conf->mutex, "cfg_cmd_status");
			iface = int_get(pfx->interface_id);
			OS_Mutex_Lock(&g_conf->mutex, "cfg_cmd_status");

			sock_printf(sock, "%s/%u %s %s %s\n",
				buf1, pfx->length,
				buf2,
				iface ? iface->name : "",
				pfx->synced ? "R" : "r");
			OS_Mutex_Release(&iface->mutex, "cfg_cmd_status");
		}
		OS_Mutex_Release(&g_conf->mutex, "cfg_cmd_status");
		sock_printf(sock, "\n");
	}

	if (!ok) sock_printf(sock, "No such status: %s\n", args);

	sock_printf(sock, "+OK Status complete\n");
	return true;
}

bool cfg_cmd_quit(int sock, const char UNUSED *args);
bool cfg_cmd_quit(int sock, const char UNUSED *args)
{
	sock_printf(sock, "+OK Thank you for using this SixXS Service\n");
	return false;
}

bool cfg_cmd_sync(int sock, const char UNUSED *args);
bool cfg_cmd_sync(int sock, const char UNUSED *args)
{
	sock_printf(sock, "+OK Syncing\n");
	sync_complete();
	sock_printf(sock, "+OK Syncing Done\n");
	return true;
}

bool cfg_cmd_down(int sock, const char UNUSED *args);
bool cfg_cmd_down(int sock, const char UNUSED *args)
{
	unsigned int		iid;
	struct sixxs_interface	*iface;

	iid = atoi(args);
	iface = int_get(iid);
	if (!iface)
	{
		sock_printf(sock, "-ERR No such interface %u\n", iid);
		return true;
	}

	if (iface->type != IFACE_PROTO41_HB && iface->type != IFACE_AYIYA)
	{
		sock_printf(sock, "-ERR Interface %u is not beatable\n", iid);
		return true;
	}

	if (iface->type == IFACE_PROTO41_HB && iface->type == IFACE_AYIYA)
	{
		/* Make it timeout */
		sock_printf(sock, "+OK Interface %u will timeout in a few\n", iid);
		iface->hb_lastbeat -= g_conf->pop_hb_timeout;
	}
	else
	{
		sock_printf(sock, "+OK Directly marking %u down\n", iid);
		int_set_state(iface, IFSTATE_DOWN);
	}

	OS_Mutex_Release(&iface->mutex, "cfg_cmd_beat");
	return true;
}

bool cfg_cmd_beat(int sock, const char UNUSED *args);
bool cfg_cmd_beat(int sock, const char UNUSED *args)
{
	unsigned int		iid;
	struct sixxs_interface	*iface;
	unsigned int		fields = countfields(args);
	char			buf[100];
	struct in_addr		ipv4;

	if (fields != 2)
	{
		sock_printf(sock, "-ERR Requires <interface-id> <ipv4-endpoint>\n");
		return true;
	}

	if (!copyfield(args, 1, buf, sizeof(buf)))
	{
		sock_printf(sock, "-ERR Argument 1 broken?\n");
		return true;
	}

	iid = atoi(buf);
	iface = int_get(iid);
	if (!iface)
	{
		sock_printf(sock, "-ERR No such interface %u\n", iid);
		return true;
	}

	if (iface->type != IFACE_PROTO41_HB && iface->type != IFACE_AYIYA)
	{
		sock_printf(sock, "-ERR Interface %u is not beatable\n", iid);
		return true;
	}

	if (!copyfield(args, 2, buf, sizeof(buf)))
	{
		sock_printf(sock, "-ERR Argument 2 broken?\n");
		return true;
	}
	if (!inet_pton(AF_INET, buf, &ipv4))
	{
		sock_printf(sock, "-ERR Invalid IPv4 address: %s\n", buf);
		return true;
	}

	sock_printf(sock, "+OK Beating interface %u towards %s\n", iface->interface_id, buf);

	/* Reconfigure & Up + Beat it */
	int_set_endpoint(iface, ipv4);
	int_beat(iface);

	OS_Mutex_Release(&iface->mutex, "cfg_cmd_beat");
	return true;
}

bool cfg_cmd_getstats(int sock, const char UNUSED *args);
bool cfg_cmd_getstats(int sock, const char UNUSED *args)
{
	struct sixxs_interface	*iface;
	unsigned int	i;

	sock_printf(sock, "+OK Statistics coming up...\n");

	OS_Mutex_Lock(&g_conf->mutex, "cfg_cmd_getstats");

	/* Walk through all the interfaces */
	for (i = 0; i < g_conf->max_interfaces; i++)
	{
		iface = g_conf->interfaces + i;
		if (iface->type == IFACE_UNSPEC) continue;

		sock_printf(sock, "%s %lld %lld %lld %lld\n",
			iface->name,
			iface->inoct, iface->outoct,
			iface->inpkt, iface->outpkt);
	}

	OS_Mutex_Release(&g_conf->mutex, "cfg_cmd_getstats");

	sock_printf(sock, "+OK End of statistics\n");
	return true;
}

bool cfg_cmd_ping4(int sock, const char UNUSED *args);
bool cfg_cmd_ping4(int sock, const char UNUSED *args)
{
	sock_printf(sock, "+OK Not Implemented yet (ping4)\n");
	return true;
}

bool cfg_cmd_ping6(int sock, const char UNUSED *args);
bool cfg_cmd_ping6(int sock, const char UNUSED *args)
{
	sock_printf(sock, "+OK Not Implemented yet (ping6)\n");
	return true;
}

/* Commands as seen above */
struct {
	const char	*cmd;
	bool		(*func)(int sock, const char *args);
	const char	*comment;
} cfg_cmds[] = 
{
	/* PoP Configuration */
	{"pop_name",		cfg_cmd_pop_name,		"<popname>"},
	{"pop_ipv4",		cfg_cmd_pop_ipv4,		"<ipv4>"},
	{"pop_ipv6",		cfg_cmd_pop_ipv6,		"<ipv6>"},
	{"pop_tunnelprefix",	cfg_cmd_pop_tunnelprefix,	"<prefix>"},
	{"pop_subnetprefix",	cfg_cmd_pop_subnetprefix,	"<prefix>"},
	{"pop_tunneldevice",	cfg_cmd_pop_tunneldevice,	"<devicename>"},
	{"pop_ignoredevices",	cfg_cmd_pop_ignoredevices,	"<ignores>"},
	{"pop_hb_supported",	cfg_cmd_pop_hb_supported,	"Y|N"},
	{"pop_hb_sendinterval",	cfg_cmd_pop_hb_sendinterval,	"<number>"},
	{"pop_hb_timeout",	cfg_cmd_pop_hb_timeout,		"<number>"},
	{"pop_tinc_supported",	cfg_cmd_pop_tinc_supported,	"Y|N"},
	{"pop_tinc_device",	cfg_cmd_pop_tinc_device,	"<devicename>"},
	{"pop_tinc_config",	cfg_cmd_pop_tinc_config,	"<configfilename>"},
	{"pop",			cfg_cmd_pop,			"OK|ERR"},
	{"tunnel",		cfg_cmd_tunnel,			"<opts>"},
	{"route",		cfg_cmd_route,			"<opts>"},

	/* Traffic */
	{"getstats",		cfg_cmd_getstats,		"[<device>]"},

	/* Ping */
	{"ping4",		cfg_cmd_ping4,			"<ip4>"},
	{"ping6",		cfg_cmd_ping6,			"<ip6>"},

	/* Management */
	{"status",		cfg_cmd_status,			"all|threads|interfaces|routes"},
	{"sync",		cfg_cmd_sync,			""},
	{"beat",		cfg_cmd_beat,			"<interface id> <ipv4>"},
	{"down",		cfg_cmd_down,			"<interface id>"},

	/* Misc commands */
	{"reply",		cfg_cmd_reply,			"<opts>"},
	{"help",		cfg_cmd_help,			""},
	{"quit",		cfg_cmd_quit,			"<byestring>"},

	/* Ignored commands */
	{"config",		NULL,				"OK|ERR"},
	{"commit",		NULL,				""},
	{"",			NULL,				NULL},
	{"#",			NULL,				"<comment>"},
	{"handle",		NULL,				"<handle>"},

	{NULL,			NULL,				NULL},
};

bool cfg_cmd_help(int sock, const char UNUSED *args)
{
	int i=0;

	sock_printf(sock, "+OK Available commands\n");
	for (i=0; cfg_cmds[i].cmd; i++)
	{
		if (cfg_cmds[i].comment == NULL) continue;
		sock_printf(sock, "%-20s %s\n", cfg_cmds[i].cmd, cfg_cmds[i].comment);
	}
	sock_printf(sock, "+OK\n");
	return true;
}

bool cfg_handlecommand(int sock, const char *cmd);
bool cfg_handlecommand(int sock, const char *cmd)
{
	int i=0, len;

	for (i=0; cfg_cmds[i].cmd; i++)
	{
		len = strlen(cfg_cmds[i].cmd);
		if (strncasecmp(cfg_cmds[i].cmd, cmd, len) != 0 ||
			 (cmd[len] != ' ' && cmd[len] != '\0')) continue;
		if (cfg_cmds[i].func == NULL)
		{
			sock_printf(sock, "+OK Ignoring: %s\n", cmd);
			return true;
		}
		else return cfg_cmds[i].func(sock, &cmd[len+1]);
	}
	sock_printf(sock, "-ERR Command unknown '%s'\n", cmd);
	return true;
}

bool cfg_fromfile(const char *filename)
{
	FILE	*file = NULL;
	char	buf[1024];
	int	n;

	errno = 0;
	file = fopen(filename, "r");
	if (file == NULL)
	{
		cfg_log(LOG_ERR, "Couldn't open configuration file %s (%d): %s\n", filename, errno, strerror(errno));
		return false;
	}

	cfg_log(LOG_INFO, "Configuring from file %s\n", filename);
	
	/* Walk through the file line by line */
	while (g_conf && g_conf->running && fgets(buf, sizeof(buf), file) == buf)
	{
		/* The last char is -1 ;) */
		n = strlen(buf)-1;

		/* Empty line -> continue */
		if (n <= 0) continue;

		if (buf[n] == '\n') {buf[n] = '\0'; n--;}
		if (buf[n] == '\r') {buf[n] = '\0'; n--;}
		cfg_handlecommand(-1, buf);
	}

	/* Close the file */
	fclose(file);
	return true;
}

void *cfg_thread_client(void *arg);
void *cfg_thread_client(void *arg)
{
	struct cfg_client	*lc = (struct cfg_client *)arg;
	unsigned int		filled = 0;
	char			buf[1024], rbuf[8192];
	bool			quit = false;

	memset(buf, 0, sizeof(buf));

	sock_printf(lc->socket, "+OK SixXS PoP Service on %s ready (http://www.sixxs.net)\n", g_conf->pop_name);

	while (	!quit && g_conf && g_conf->running &&
		sock_getline(lc->socket, rbuf, (unsigned int)sizeof(rbuf), &filled, buf, (unsigned int)sizeof(buf)) > 0)
	{
		cfg_log(LOG_INFO, "Client sent '%s'\n", buf);
		quit = !cfg_handlecommand(lc->socket, buf);
	}
	
	D(cfg_log(LOG_DEBUG, "Client Finished %s:%s\n", lc->clienthost, lc->clientservice);)

	/* End this conversation */
	close(lc->socket);

	free(lc);
	return NULL;
}

/* const char url[] = "any://any:42003 any://any:42001 any://any:43002"; */
const char url[] = "any://any:42003";

void *cfg_thread(void UNUSED *arg);
void *cfg_thread(void UNUSED *arg)
{
	struct cfg_client	*lc;
	struct socketpool	pool;
	struct socketnode	*sn, *sn2;
	fd_set			fd_read;
	struct timeval		timeout;
	int			i = 0;
	struct sockaddr_storage	sa;
	socklen_t		sa_len;
	bool			needpool = true;

	/* Show that we have started */
	cfg_log(LOG_INFO, "SixXS Configuration Handler\n");

	while (g_conf && g_conf->running)
	{
		if (needpool)
		{
			/* Setup listening socket(s) */
			socketpool_init(&pool);
			if (use_uri(module, url, CFG_PORT, &pool, 42) == 0)
			{
				mdolog(LOG_ERR, "Error while trying to open the socket: %s (%d)\n", strerror(errno), errno);

				/* Try again after 5 seconds */
				sleep(5);
				continue;
			}
			else
			{
				/* Make all the sockets nonblocking */
				List_For (&pool.sockets, sn, sn2, struct socketnode *)
				{
					socket_setnonblock(sn->socket);
				}

				needpool = false;
			}
		}

		/* What we want to know */
		memcpy(&fd_read, &pool.fds, sizeof(fd_read));

		/* Timeout */
		memset(&timeout, 0, sizeof(timeout));
		timeout.tv_sec = 5;

		i = select(pool.hi+1, &fd_read, NULL, NULL, &timeout);

		if (i < 0)
		{
			if (errno == EINTR) continue;
			mdolog(LOG_ERR, "Select failed: %s (%d)\n", strerror(errno), errno);
			socketpool_exit(&pool);
			needpool = true;
			continue;
		}

		List_For (&pool.sockets, sn, sn2, struct socketnode *)
		{
			if (!FD_ISSET(sn->socket, &fd_read)) continue;

			lc = malloc(sizeof(*lc));
			if (!lc)
			{
				mdolog(LOG_ERR, "Out of memory during cfg_thread(): %s (%d)\n", strerror(errno), errno);
				break;
			}

			sa_len = sizeof(sa);
			memset(lc, 0, sizeof(*lc));
			memset(&sa, 0, sa_len);

			/* Incoming connection */
			lc->socket = accept(sn->socket, (struct sockaddr *)&sa, &sa_len);
			if (lc->socket == -1)
			{
				mdolog(LOG_WARNING, "Accept failed: %s (%d)\n", strerror(errno), errno);
			}
			else
			{
				i = getnameinfo((struct sockaddr *)&sa, sa_len,
					lc->clienthost, sizeof(lc->clienthost),
					lc->clientservice, sizeof(lc->clientservice),
					NI_NUMERICHOST|NI_NUMERICSERV);
				if (i != 0)
				{
					sock_printf(lc->socket, "-ERR I couldn't find out who you are.. go away!\n");
					/* Error on resolve */
					cfg_log(LOG_ERR, "Error %d : %s (family: %d)\n", i, gai_strerror(i), sa.ss_family);
					close(lc->socket);
				}

				D(cfg_log(LOG_DEBUG, "Accepted %s:%s\n", lc->clienthost, lc->clientservice);)

				thread_add("CfgClient", cfg_thread_client, lc, true);
				lc = NULL;
			}

			/* Free the client memory when not launched */
			if (lc) lc = NULL;
		}
	}

	/* Exit */
	socketpool_exit(&pool);

	return NULL;
}

void cfg_init(void)
{
	/* Create a thread for the Configuration Handler */
	thread_add("Cfg", cfg_thread, NULL, true);
}

