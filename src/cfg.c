/**************************************
 SixXSd - SixXS POP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
***************************************
 $Author: jeroen $
 $Id: cfg.c,v 1.4 2005-11-30 16:19:02 jeroen Exp $
 $Date: 2005-11-30 16:19:02 $

 SixXSd Configuration Handler
**************************************/

#include "sixxsd.h"

#define CFG_PORT "42003"

void cfg_log(int level, char *fmt, ...)
{
	char buf[1024];
	
	// Print the host+port this is coming from
	snprintf(buf, sizeof(buf), "[Cfg:0x%x] : ", (unsigned int)pthread_self());

	// Print the log message behind it
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf+strlen(buf), sizeof(buf)-strlen(buf), fmt, ap);
	va_end(ap);
	
	// Actually Log it
	dolog(level, buf);
}

/********************************************************************
  POP Commands
********************************************************************/
bool cfg_cmd_pop_name(int sock, char *args)
{
	if (g_conf->pop_name) free(g_conf->pop_name);
	g_conf->pop_name = strdup(args);
	sock_printf(sock, "+OK Accepted POP Name\n");
	return true;
}

bool cfg_cmd_pop_ipv4(int sock, char *args)
{
	if (!inet_pton(AF_INET, args, &g_conf->pop_ipv4))
	{
		sock_printf(sock, "-ERR argument (%s) didn't specify a valid IPv4 address\n", args);
		return false;
	}
	sock_printf(sock, "+OK POP now has IPv4 address %s\n", args);
	return true;
}

bool cfg_cmd_pop_ipv6(int sock, char *args)
{
	if (!inet_pton(AF_INET6, args, &g_conf->pop_ipv6))
	{
		sock_printf(sock, "-ERR argument (%s) didn't specify a valid IPv6 address\n", args);
		return false;
	}
	sock_printf(sock, "+OK POP now has IPv6 address %s\n", args);
	return true;
}

bool cfg_cmd_pop_tunnelprefix(int sock, char *args)
{
	sock_printf(sock, "+OK Command not implemented - ignoring\n");
	return true;
}

bool cfg_cmd_pop_subnetprefix(int sock, char *args)
{
	sock_printf(sock, "+OK Command not implemented - ignoring\n");
	return true;
}

bool cfg_cmd_pop_tunneldevice(int sock, char *args)
{
	if (g_conf->pop_tunneldevice) free(g_conf->pop_tunneldevice);
	g_conf->pop_tunneldevice = strdup(args);
	sock_printf(sock, "+OK Accepted POP Tunnel Device %s\n", args);
	return true;
}

bool cfg_cmd_pop_ignoredevices(int sock, char *args)
{
	if (g_conf->pop_ignoredevices) free(g_conf->pop_ignoredevices);
	g_conf->pop_ignoredevices = strdup(args);
	sock_printf(sock, "+OK Accepted POP Tunnel Device %s\n", args);
	return true;
}

bool cfg_cmd_pop_hb_supported(int sock, char *args)
{
	if (strcmp(args, "Y") == 0) g_conf->pop_hb_supported = true;
	else g_conf->pop_hb_supported = false;
	sock_printf(sock, "+OK POP %s Heartbeats\n",  g_conf->pop_hb_supported ? "supports" : "doesn't support");
	return true;
}

bool cfg_cmd_pop_hb_sendinterval(int sock, char *args)
{
	g_conf->pop_hb_sendinterval = atoi(args);
	sock_printf(sock, "+OK POP Heartbeat Send Interval now %d\n",  g_conf->pop_hb_sendinterval);
	return true;
}

bool cfg_cmd_pop_hb_timeout(int sock, char *args)
{
	g_conf->pop_hb_timeout = atoi(args);
	sock_printf(sock, "+OK POP Heartbeat Timeout now %d\n",  g_conf->pop_hb_timeout);
	return true;
}

bool cfg_cmd_pop_tinc_supported(int sock, char *args)
{
	if (strcmp(args, "Y") == 0) g_conf->pop_tinc_supported = true;
	else g_conf->pop_tinc_supported = false;
	sock_printf(sock, "+OK POP %s tinc\n",  g_conf->pop_tinc_supported ? "supports" : "doesn't support");
	return true;
}

bool cfg_cmd_pop_tinc_device(int sock, char *args)
{
	if (g_conf->pop_tinc_device) free(g_conf->pop_tinc_device);
	g_conf->pop_tinc_device = strdup(args);
	sock_printf(sock, "+OK Accepted tinc Device %s\n", args);
	return true;
}

bool cfg_cmd_pop_tinc_config(int sock, char *args)
{
	if (g_conf->pop_tinc_config) free(g_conf->pop_tinc_config);
	g_conf->pop_tinc_config = strdup(args);
	sock_printf(sock, "+OK Accepted tinc config %s\n", args);
	return true;
}

// TUNNEL
// "tunnel <devicenumber> <ipv6_us> <ipv6_them> <ipv6_prefixlen> <ipv4_us> <ipv4_them|heartbeat|tinc|ayiya> <up|disabled|down> <mtu> [<heartbeatpassword>]"
// Note: ipv4_us is ignored, should be the same everywhere
bool cfg_cmd_tunnel(int sock, char *args)
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

	// Get the devicenumber
	if (!copyfield(args, 1, buf, sizeof(buf))) return false;
	id = strtol(buf, (char **)NULL, 10);
	if (id == 0)
	{
		cfg_log(LOG_WARNING, "Invalid interface number '%s'\n", buf);
		return false;
	}

	// Get the ipv6_us address
	if (!copyfield(args, 2, buf, sizeof(buf))) return false;
	if (!inet_pton(AF_INET6, buf, &ipv6_us))
	{
		cfg_log(LOG_WARNING, "Invalid IPv6_us address '%s'\n", buf);
		return false;
	}

	// Get the ipv6_them address
	if (!copyfield(args, 3, buf, sizeof(buf))) return false;
	if (!inet_pton(AF_INET6, buf, &ipv6_them))
	{
		cfg_log(LOG_WARNING, "Invalid IPv6_them address '%s'\n", buf);
		return false;
	}

	// Get the prefixlen
	if (!copyfield(args, 4, buf, sizeof(buf))) return false;
	prefixlen = atoi(buf);

	// Get the ipv4_them address
	memset(&ipv4_them, 0, sizeof(ipv4_them));
	if (!copyfield(args, 6, buf, sizeof(buf))) return false;
	if (strcasecmp(buf, "heartbeat") == 0) type = IFACE_PROTO41_HB;
	else if (strcasecmp(buf, "tinc") == 0) type = IFACE_TINC;
	else if (strcasecmp(buf, "ayiya") == 0) type = IFACE_AYIYA;
	else if (inet_pton(AF_INET, buf, &ipv4_them)) type = IFACE_PROTO41;
	else
	{
		cfg_log(LOG_WARNING, "Unknown value for IPv4_them '%s'\n", buf);
		return false;
	}

	// Get the interface state
	if (!copyfield(args, 7, buf, sizeof(buf))) return false;
	if (strcmp(buf, "up") == 0)
	{
		// Dynamic tunnels start in down state
		// and are marked up on the first receival
		// of a Heartbeat packet, thus client initiated
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
		cfg_log(LOG_WARNING, "Unknown interface state '%s'\n", buf);
		return false;
	}

	/* MTU size */
	if (!copyfield(args, 8, buf, sizeof(buf))) return false;
	mtu = atoi(buf);

	// Get the password (if it exists)
	if (fields == 9 && !copyfield(args, 9, buf, sizeof(buf))) return false;

	int_reconfig(id, &ipv6_us, &ipv6_them, prefixlen, ipv4_them, type, state, mtu, fields == 9 ? buf : NULL);

	sock_printf(sock, "+OK Tunnel %u accepted\n", id);
	return true;
}

// ROUTE
// "route <prefix>/<prefixlen> <nexthop> <up|disabled|down> <static|bgp>"
bool cfg_cmd_route(int sock, char *args)
{
	char			buf[1024];
	unsigned int		fields = countfields(args), length = 128, i;
	bool			enabled = false;
	struct in6_addr		prefix, nexthop;
	struct sixxs_prefix	*pfx;

	if (fields != 4)
	{
		sock_printf(sock, "-ERR route requires 4 arguments, got %u : '%s'\n", fields, args);
		return true;
	}

	/* XXX - Parse Route Type */

	if (!copyfield(args, 4, buf, sizeof(buf))) return false;
	if (strcmp(buf, "up") == 0) enabled = true;
	else if (strcmp(buf, "down") == 0) enabled = false;
	else
	{
		// Ignore disabled devices
		return true;
	}

	// Get the prefix
	if (!copyfield(args, 1, buf, sizeof(buf))) return false;

	// Find the slash
	for (i=0; buf[i] != '\0' && buf[i] != '/'; i++);
	if (buf[i] == '\0') length = 128;
	else
	{
		buf[i] = '\0';
		i++;
		length = atoi(&buf[i]);
	}

	if (!inet_pton(AF_INET6, buf, &prefix))
	{
		cfg_log(LOG_WARNING, "Invalid prefix address '%s'\n", buf);
		return false;
	}

	if (!copyfield(args, 2, buf, sizeof(buf))) return false;
	if (!inet_pton(AF_INET6, buf, &nexthop))
	{
		cfg_log(LOG_WARNING, "Invalid nexthop address '%s'\n", buf);
		return false;
	}

	// Lookup which interface it belongs to
	pfx = pfx_get(&nexthop, 128);
	if (!pfx)
	{
		cfg_log(LOG_WARNING, "Couldn't find nexthop '%s' while determining interface_id\n", buf);
		return false;
	}

	// Add the route
	pfx_reconfig(&prefix, length, &nexthop, enabled, false, pfx->interface_id);

	sock_printf(sock, "+OK Route accepted\n");
	return true;
}

// MISC
bool cfg_cmd_help(int sock, char *args);
// Defined after cfg_cmds

bool cfg_cmd_reply(int sock, char *args)
{
	sock_printf(sock, "+OK You mentioned: %s\n", args);
	return true;
}

bool cfg_cmd_status(int sock, char *args)
{
	struct sixxs_thread 	*t = NULL;
	pthread_t		thread = pthread_self();
	unsigned int		i;
	struct sixxs_interface	*iface = NULL;
	struct sixxs_prefix	*pfx = NULL;
	char			buf1[1024], buf2[1024];

	sock_printf(sock, "+OK Status coming up...\n");

	sock_printf(sock, "Threads:\n");
	for (t = g_conf->threads; t; t = t->next)
	{
		sock_printf(sock, "Thread 0x%x : %s%s\n",
			(void *)t->thread, t->description,
			pthread_equal(t->thread, thread) ? " (this)" : "");
	}
	sock_printf(sock, "\n");

	sock_printf(sock, "Interfaces:\n");
	// Walk through all the interfaces
	for (i = 0; i < g_conf->max_interfaces; i++)
	{
		iface = g_conf->interfaces + i;
		if (iface->type == IFACE_UNSPEC) continue;

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
			snprintf(buf2, sizeof(buf2), "proto41_hb %s", buf1);
			break;
		case IFACE_TINC:
			snprintf(buf2, sizeof(buf2), "tinc");
			break;
		case IFACE_AYIYA:
			snprintf(buf2, sizeof(buf2), "ayiya %s %u %s",
				buf1,
				iface->ayiya_port,
				iface->ayiya_protocol == 0		? "unused" :
				iface->ayiya_protocol == IPPROTO_UDP	? "udp" :
				iface->ayiya_protocol == IPPROTO_TCP	? "tcp"
									: "unknown");
			break;
		default:
			snprintf(buf2, sizeof(buf2), "unknown - WARNING!");
		}

		sock_printf(sock, "%s %u %s %lld %lld %lld %lld %s\n",
			iface->name, i,
			iface->state == IFSTATE_DISABLED	? "disabled" :
			iface->state == IFSTATE_UP		? "up" :
			iface->state == IFSTATE_DOWN		? "down"
								: "!unknown!",
			iface->inoct, iface->outoct,
			iface->inpkt, iface->outpkt,
			buf2);
	}
	sock_printf(sock, "\n");

	sock_printf(sock, "Routes:\n");
	// Walk through all the interfaces
	for (i = 0; i < g_conf->max_prefixes; i++)
	{
		pfx = g_conf->prefixes + i;
		if (!pfx->valid) continue;

		memset(buf1, 0, sizeof(buf1));
		inet_ntop(AF_INET6, &pfx->prefix, buf1, sizeof(buf1));

		memset(buf2, 0, sizeof(buf2));
		inet_ntop(AF_INET6, &pfx->nexthop, buf2, sizeof(buf2));
		
		iface = int_get(pfx->interface_id);

		sock_printf(sock, "%s/%u %s %s\n", buf1, pfx->length, buf2, iface ? iface->name : "");
	}
	sock_printf(sock, "\n");

	sock_printf(sock, "+OK Status complete\n");
	return true;
}

bool cfg_cmd_quit(int sock, char *args)
{
	sock_printf(sock, "+OK Thank you for using this SixXS Service\n");
	return false;
}

// Commands as seen above
struct {
	char *cmd;
	bool (*func)(int sock, char *args);
} cfg_cmds[] = 
{
	// POP Configuration
	{"pop_name",		cfg_cmd_pop_name},
	{"pop_ipv4",		cfg_cmd_pop_ipv4},
	{"pop_ipv6",		cfg_cmd_pop_ipv6},
	{"pop_tunnelprefix",	cfg_cmd_pop_tunnelprefix},
	{"pop_subnetprefix",	cfg_cmd_pop_subnetprefix},
	{"pop_tunneldevice",	cfg_cmd_pop_tunneldevice},
	{"pop_ignoredevices",	cfg_cmd_pop_ignoredevices},
	{"pop_hb_supported",	cfg_cmd_pop_hb_supported},
	{"pop_hb_sendinterval",	cfg_cmd_pop_hb_sendinterval},
	{"pop_hb_timeout",	cfg_cmd_pop_hb_timeout},
	{"pop_tinc_supported",	cfg_cmd_pop_tinc_supported},
	{"pop_tinc_device",	cfg_cmd_pop_tinc_device},
	{"pop_tinc_config",	cfg_cmd_pop_tinc_config},
	{"pop",			NULL},

	// Tunnel & Route
	{"tunnel",		cfg_cmd_tunnel},
	{"route",		cfg_cmd_route},
	
	// Ignored commands
	{"config",		NULL},
	{"commit",		NULL},
	{"",			NULL},
	{"#",			NULL},
	{"handle",		NULL},

	// Misc commands
	{"status",		cfg_cmd_status},
	{"reply",		cfg_cmd_reply},
	{"help",		cfg_cmd_help},
	{"quit",		cfg_cmd_quit},
	{NULL,			NULL},
};

bool cfg_cmd_help(int sock, char *args)
{
	int i=0;

	sock_printf(sock, "+OK Available commands\n");
	for (i=0; cfg_cmds[i].cmd; i++)
	{
		if (cfg_cmds[i].func == NULL) continue;
		sock_printf(sock, "%s\n", cfg_cmds[i].cmd);
	}
	sock_printf(sock, "+OK\n");
	return true;
}

bool cfg_handlecommand(int sock, char *cmd)
{
	int i=0, len;

	for (i=0; cfg_cmds[i].cmd; i++)
	{
		len = strlen(cfg_cmds[i].cmd);
		if (strncasecmp(cfg_cmds[i].cmd, cmd, len) != 0 ||
			 (cmd[len] != ' ' && cmd[len] != '\0')) continue;
		if (cfg_cmds[i].func == NULL)
		{
			sock_printf(sock, "+OK Ignoring...\n");
			return true;
		}
		else return cfg_cmds[i].func(sock, &cmd[len+1]);
	}
	sock_printf(sock, "-ERR Command unknown '%s'\n", cmd);
	return true;
}

bool cfg_fromfile(char *filename)
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

	cfg_log(LOG_ERR, "Configuring from file %s\n", filename);
	
	// Walk through the file line by line
	while (fgets(buf, sizeof(buf), file) == buf)
	{
		// The last char is -1 ;)
		n = strlen(buf)-1;

		// Empty line -> continue
		if (n <= 0) continue;

		if (buf[n] == '\n') {buf[n] = '\0'; n--;}
		if (buf[n] == '\r') {buf[n] = '\0'; n--;}
		cfg_handlecommand(-1, buf);
	}

	// Close the file
	fclose(file);
	return true;
}

void *cfg_thread_client(void *arg)
{
	int			listenfd = (int)arg;
	int			sock, n, filled = 0;
	char			clienthost[NI_MAXHOST];
	char			clientservice[NI_MAXSERV];
	struct sockaddr_storage	ci;
	socklen_t		cl;
	char			buf[1024], rbuf[1024];
	bool			quit = false;

	memset(buf, 0, sizeof(buf));
	memset(&ci, 0, sizeof(ci));
	cl = sizeof(ci);

	// Try to accept a client
	D(cfg_log(LOG_DEBUG, "Accepting new clients...\n");)
	sock = accept(listenfd, (struct sockaddr *)&ci, &cl);
	
	if (sock == -1)
	{
		cfg_log(LOG_ERR, "Accept failed (%d) : %s\n", errno, strerror(errno));
		return NULL;
	}

	D(cfg_log(LOG_DEBUG, "Accept success (%d) : %s\n", errno, strerror(errno));)

	// Create a new thread for which is going to handle accepts
	// Recursive thread creation for accepts ;)
	thread_add("Cfg", cfg_thread_client, (void *)listenfd);

	// We have accepted a client
	// Check if it is actually allowed to access us

	memset(clienthost, 0, sizeof(clienthost));
	memset(clientservice, 0, sizeof(clientservice));

	n = getnameinfo((struct sockaddr *)&ci, cl,
		clienthost, sizeof(clienthost),
		clientservice, sizeof(clientservice),
		NI_NUMERICHOST);
	if (n != 0)
	{
		sock_printf(sock, "-ERR I couldn't find out who you are.. go away!\n");
		// Error on resolve
		cfg_log(LOG_ERR, "Error %d : %s (family: %d)\n", n, gai_strerror(n), ci.ss_family);
		close(sock);
		return NULL;
	}

	D(cfg_log(LOG_DEBUG, "Accepted %s:%s\n", clienthost, clientservice);)

	sock_printf(sock, "+OK SixXSd Configuration Service on %s ready (http://www.sixxs.net)\n", g_conf->pop_name);

	while (	!quit &&
		sock_getline(sock, rbuf, sizeof(rbuf), &filled, buf, sizeof(buf)) > 0)
	{
		cfg_log(LOG_INFO, "Client sent '%s'\n", buf);
		quit = !cfg_handlecommand(sock, buf);
	}
	
	D(cfg_log(LOG_DEBUG, "Client Finished %s:%s\n", clienthost, clientservice);)

	// End this conversation
	close(sock);
	return NULL;
}

void *cfg_thread(void *arg)
{
	int			listenfd;
	char			host[NI_MAXHOST];

	// Show that we have started
	cfg_log(LOG_INFO, "SixXS Configuration Handler\n");

	if (!inet_ntop(AF_INET, &g_conf->pop_ipv4, host, sizeof(host)))
	{
		cfg_log(LOG_ERR, "[Cfg] Error, pop_ipv4 not set to a valid IPv4 address\n");
		return NULL;
	}

	/* Setup listening socket */
	listenfd = listen_server("Cfg", host, CFG_PORT, AF_INET, SOCK_STREAM);
	if (listenfd < 0)
	{
		cfg_log(LOG_ERR, "listen_server error:: could not create listening socket\n");
		return NULL;
	}

	cfg_thread_client((void *)listenfd);
	return NULL;
}

