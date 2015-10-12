/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2015 All Rights Reserved
************************************************************
 SixXS Daemon - Socket Proxy
***********************************************************/

#include "sixxsd.h"
#include "common_extra.h"

const char module_pproxy[] = "pproxy";
#define module module_pproxy

VOID pproxy_handle_conn(struct socketnode *sn, bool in);
VOID pproxy_handle_conn(struct socketnode *sn, bool in)
{
/*
	struct sixxsd_pproxy		*sp;
	struct sixxsd_pproxy_conn	*sc;
*/
	if (in && sn)
	{
		sn = NULL;
	}
}

static PTR *pproxy_thread(PTR UNUSED *arg);
static PTR *pproxy_thread(PTR UNUSED *arg)
{
	struct socketpool		*pool = &g_conf->pproxy_pool;
	int				n;
	fd_set				fd_read, fd_send;
	struct sixxsd_pproxy_conn	*ppc = NULL;
	struct timeval			timeout;
	struct socketnode		*sn, *sn2;
	struct sockaddr_storage		sa;
	socklen_t			sa_len;

	while (g_conf && g_conf->running)
	{
		if (!g_conf->running) break;

		/* What we want to know about */
		memcpy(&fd_read, &pool->fds, sizeof(fd_read));
		memcpy(&fd_send, &pool->fds, sizeof(fd_send));

		/* Timeout */
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;

		thread_setstate(thread_state_selectwait);
		n = select(pool->hi+1, &fd_read, &fd_send, NULL, &timeout);
		thread_setstate(thread_state_running);

		if (n < 0)
		{
			/* Ignore signals, appropriate flags will be set to handle them */
			if (errno == EINTR)
			{
				continue;
			}
			else
			{
				mdoelog(LOG_ERR, errno, "Select failed\n");
			}
			break;
		}

		if (!g_conf || !g_conf->running) break;

		List_For (&pool->sockets, sn, sn2, struct socketnode *)
		{
			if (sn->data != NULL)
			{
				if (FD_ISSET(sn->socket, &fd_read))
				{
					/* Forward the bits */
					pproxy_handle_conn(sn, true);
				}

				if (FD_ISSET(sn->socket, &fd_send))
				{
					/* Forward the bits */
					pproxy_handle_conn(sn, false);
				}
			}
			else
			{
				if (!FD_ISSET(sn->socket, &fd_read)) continue;

				/* New incoming connection */
				sa_len = sizeof(sa);
				ppc->remote = accept(sn->socket, (struct sockaddr *)&sa, &sa_len);
				if (ppc->remote == -1)
				{
					mdoelog(LOG_WARNING, errno, "Socket Accept failed on %s\n", sock_name(sn->socktype));
				}
				else
				{
					IPADDRESS	ip;

					ipaddress_make_ss(&ip, &sa);
					port_make(&ppc->portnum, &sa);
				}

			} /* Portproxy or accept */

		} /* List_For (&pool->sockets, sn, sn2, struct socketnode *) */

	} /* while (g_conf && g_conf->running) */

	socketpool_exit(pool);

	mddolog("Portproxy loop exited, going down...\n");
	return 0;
}

int pproxy_init(struct sixxsd_context *ctx)
{
	char			buf[1024];
	struct socketnode	*sn, *sn2;

	memzero(buf, sizeof(buf));

	/* Open the URI */
	socketpool_init(&g_conf->pproxy_pool);
	if (use_uri(buf, sizeof(buf), false, "any://any:42006", "42006", &g_conf->pproxy_pool, 42) == 0)
	{
		if (strlen(buf) > 0) ctx_printf(ctx, "%s", buf);
		ctx_printef(ctx, errno, "Error while trying to open the PortProxy socket\n");
		return 0;
	}

	if (strlen(buf) > 0) ctx_printf(ctx, "%s", buf);

	ctx_flush(ctx, 200);

	/* Make all the sockets nonblocking and support IP_TRANSPARENT */
	List_For (&g_conf->pproxy_pool.sockets, sn, sn2, struct socketnode *)
	{
		int on;

		sock_setnonblock(sn->socket);

		on = 1;
		setsockopt(sn->socket, SOL_IP, IP_TRANSPARENT, &on, sizeof(on));
	}

	if (!thread_add(ctx, "PortProxy", pproxy_thread, NULL, NULL, true)) return 400;

	return 200;
}

static int pproxy_cmd_set_config(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char *args[]);
static int pproxy_cmd_set_config(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char *args[])
{
	struct sixxsd_pproxy	*pp;
	uint16_t		poff;
	unsigned int		tmp, arg = 0;

	if (sscanf(args[arg], "%x", &tmp) != 1)
	{
		ctx_printf(ctx, "Invalid port offset (%s) - not a hex number\n", args[arg]);
		return 400;
	}
	poff = tmp;

	if (poff > lengthof(g_conf->pproxies))
	{
		ctx_printf(ctx, "Port offset 0x%x is out of range (0x%u)\n", poff, (unsigned int)lengthof(g_conf->pproxies));
		return 400;
	}

	pp = &g_conf->pproxies[poff];

	/* Update the Hi Tunnel marker */
	if (poff > g_conf->pproxy_hi) g_conf->pproxy_hi = poff;

	/* The port proxy id (P<xxx>) */
	arg++;
	if (sscanf(args[arg], "%u", &tmp) != 1)
	{
		ctx_printf(ctx, "Invalid port number (%s) - not a number\n", args[arg]);
		return 400;
	}
	pp->pproxy_id = tmp;

	/* The destination host / IP */
	arg++;
	if (strlen(args[arg]) > sizeof(pp->dest_name) - 2)
	{
		ctx_printf(ctx, "Destination name (%s) too long\n", args[arg]);
		return 400;
	}

	/* Did it change? */
	if (strcmp(pp->dest_name, args[arg]) != 0)
	{
		/* Update it */
		strncpy(pp->dest_name, args[arg], sizeof(pp->dest_name));

		/* Invalidate lookup cache */
		pp->dest_lastlookup = 0;
	}

	/* The destination port */
	arg++;
	if (sscanf(args[arg], "%u", &tmp) != 1)
	{
		ctx_printf(ctx, "Invalid port number (%s) - not a number\n", args[arg]);
		return 400;
	}
	pp->dest_port = tmp;

	ctx_printf(ctx, "Port Proxy P%u configured", pp->pproxy_id);
	return 200;
}

struct ctx_menu ctx_menu_pproxy_set[] =
{
	{"set",			NULL, 0,0, NULL, NULL },
	{"config",		pproxy_cmd_set_config,	4, 4,	"<poff> <pid> <dest_name> <dest_port>",	"Configure a Port Proxy" },
	{NULL,			NULL, 0,0, NULL, NULL },
};

CONTEXT_MENU(pproxy_set)
CONTEXT_CMD(pproxy_set)

struct ctx_menu ctx_menu_pproxy[] =
{
	{"pproxy",	NULL,			0,0,	NULL,		NULL },
/*	{"get",		ctx_cmd_pproxy_get,	0,-1,	CONTEXT_SUB,	"Get configuration information" }, */
	{"set",		ctx_cmd_pproxy_set,	0,-1,	CONTEXT_SUB,	"Set configuration information" },
/*	{"show",	pproxy_cmd_show,	1,1,	"<sid>",	"Show the configuration of a single tunnel" }, */
/*	{"list",	tunnel_cmd_list,	0,0,	NULL,		"List a summary of the sockets" }, */
	{NULL,		NULL,			0,0,	NULL,		NULL },
};

CONTEXT_CMD(pproxy)

