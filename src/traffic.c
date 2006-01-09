/**************************************
 SixXSd - SixXS PoP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
***************************************
 $Author: jeroen $
 $Id: traffic.c,v 1.3 2006-01-09 19:16:24 jeroen Exp $
 $Date: 2006-01-09 19:16:24 $

 SixXSd Traffic Handler
**************************************/

#include "sixxsd.h"

const char module_traffic[] = "traffic";
#define module module_traffic

#define TRAFFIC_PORT "42002"

void traffic_log(int level, const char *fmt, ...);
void traffic_log(int level, const char *fmt, ...)
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

bool traffic_cmd_getstats(int sock, const char UNUSED *args);
bool traffic_cmd_getstats(int sock, const char UNUSED *args)
{
	struct sixxs_interface	*iface;
	unsigned int		i;

	sock_printf(sock, "+OK Statistics coming up...\n");

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

	sock_printf(sock, "+OK End of statistics\n");
	return true;
}

/* MISC */
bool traffic_cmd_help(int sock, const char UNUSED *args);
/* Defined after traffic_cmds */

bool traffic_cmd_reply(int sock, const char *args);
bool traffic_cmd_reply(int sock, const char *args)
{
	sock_printf(sock, "+OK You mentioned: %s\n", args);
	return true;
}

bool traffic_cmd_quit(int sock, const char UNUSED *args);
bool traffic_cmd_quit(int sock, const char UNUSED *args)
{
	sock_printf(sock, "+OK Thank you for using this SixXS Service\n");
	return false;
}

/* Commands as seen above */
struct {
	const char *cmd;
	bool (*func)(int sock, const char *args);
} traffic_cmds[] = 
{
	/* Tunnel & Route */
	{"getstats",		traffic_cmd_getstats},
	
	/* Ignored commands */
	{"",			NULL},

	/* Misc commands */
	{"reply",		traffic_cmd_reply},
	{"help",		traffic_cmd_help},
	{"quit",		traffic_cmd_quit},
	{NULL,			NULL},
};

bool traffic_cmd_help(int sock, const char UNUSED *args)
{
	int i=0;

	sock_printf(sock, "+OK Available commands\n");
	for (i=0; traffic_cmds[i].cmd; i++)
	{
		if (traffic_cmds[i].func == NULL) continue;
		sock_printf(sock, "%s\n", traffic_cmds[i].cmd);
	}
	sock_printf(sock, "+OK\n");
	return true;
}

bool traffic_handlecommand(int sock, const char *cmd);
bool traffic_handlecommand(int sock, const char *cmd)
{
	int i=0, len;

	for (i=0; traffic_cmds[i].cmd; i++)
	{
		len = strlen(traffic_cmds[i].cmd);
		if (strncasecmp(traffic_cmds[i].cmd, cmd, len) != 0 ||
			 (cmd[len] != ' ' && cmd[len] != '\0')) continue;

		if (traffic_cmds[i].func == NULL)
		{
			sock_printf(sock, "+OK Ignoring...\n");
			return true;
		}
		else return traffic_cmds[i].func(sock, &cmd[len+1]);
	}
	sock_printf(sock, "-ERR Command unknown '%s'\n", cmd);
	return true;
}

void *traffic_thread_client(void *arg);
void *traffic_thread_client(void *arg)
{
	int			listenfd = (int)arg;
	int			sock, n;
	unsigned int		filled = 0;
	char			clienthost[NI_MAXHOST];
	char			clientservice[NI_MAXSERV];
	struct sockaddr_storage	ci;
	socklen_t		cl;
	char			buf[1024], rbuf[1024];
	bool			quit = false;

	memset(buf, 0, sizeof(buf));
	memset(&ci, 0, sizeof(ci));
	cl = sizeof(ci);

	/* Try to accept a client */
	D(traffic_log(LOG_DEBUG, "Accepting new clients...\n");)
	sock = accept(listenfd, (struct sockaddr *)&ci, &cl);
	
	if (sock == -1)
	{
		traffic_log(LOG_ERR, "Accept failed (%d) : %s\n", errno, strerror(errno));
		return NULL;
	}

	D(traffic_log(LOG_DEBUG, "Accept success (%d) : %s\n", errno, strerror(errno));)

	/* Create a new thread for which is going to handle accepts */
	/* Recursive thread creation for accepts ;) */
	thread_add("Traffic", traffic_thread_client, (void *)listenfd, true);

	/* We have accepted a client */
	/* Check if it is actually allowed to access us */

	memset(clienthost, 0, sizeof(clienthost));
	memset(clientservice, 0, sizeof(clientservice));

	n = getnameinfo((struct sockaddr *)&ci, cl,
		clienthost, sizeof(clienthost),
		clientservice, sizeof(clientservice),
		NI_NUMERICHOST);
	if (n != 0)
	{
		sock_printf(sock, "-ERR I couldn't find out who you are.. go away!\n");
		/* Error on resolve */
		traffic_log(LOG_ERR, "Error %d : %s (family: %d)\n", n, gai_strerror(n), ci.ss_family);
		close(sock);
		return NULL;
	}

	D(traffic_log(LOG_DEBUG, "Accepted %s:%s\n", clienthost, clientservice);)

	sock_printf(sock, "+OK SixXSd Traffic Service on %s ready (http://www.sixxs.net)\n", g_conf->pop_name);

	while (	!quit &&
		sock_getline(sock, rbuf, (unsigned int)sizeof(rbuf), &filled, buf, (unsigned int)sizeof(buf)) > 0)
	{
		traffic_log(LOG_INFO, "Client sent '%s'\n", buf);
		quit = !traffic_handlecommand(sock, buf);
	}
	
	D(traffic_log(LOG_DEBUG, "Client Finished %s:%s\n", clienthost, clientservice);)

	/* End this conversation */
	close(sock);
	return NULL;
}

void *traffic_thread(void UNUSED *arg);
void *traffic_thread(void UNUSED *arg)
{
	int			listenfd;
	char			host[NI_MAXHOST];

	/* Show that we have started */
	traffic_log(LOG_INFO, "SixXS Traffic Handler\n");

	if (!inet_ntop(AF_INET, &g_conf->pop_ipv4, host, sizeof(host)))
	{
		traffic_log(LOG_ERR, "Error, pop_ipv4 not set to a valid IPv4 address\n");
		return NULL;
	}

	/* Setup listening socket */
	listenfd = listen_server("traffic", host, TRAFFIC_PORT, AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0);
	if (listenfd < 0)
	{
		traffic_log(LOG_ERR, "listen_server error:: could not create listening socket\n");
		return NULL;
	}

	traffic_thread_client((void *)listenfd);
	return NULL;
}

void traffic_init(void)
{
	/* Create a thread for the Statistics Handler */
	thread_add("Traffic", traffic_thread, NULL, true);
}

