/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2012 All Rights Reserved
************************************************************
 SixXSd Configuration
***********************************************************/

#include "sixxsd.h"

const char module_config[] = "config";
#define module module_config

struct sixxsd_configuration *g_conf = NULL;

/* Debugging */
#define DD(x) {}
/* #define DD(x) x */

/* Initialize our configuration */
int cfg_init(struct sixxsd_context *ctx, uint32_t verbose)
{
	struct sixxsd_tunnels	*tuns;
	struct sixxsd_tunnel	*tun;
	struct sixxsd_subnets	*subs;
	unsigned int		i, j;

	i = sizeof(struct sixxsd_configuration);
	ctx_printf(ctx, "Allocating a configuration structure of %u bytes\n", i);
	g_conf = (struct sixxsd_configuration *)mcalloc(i, "g_conf");
	if (!g_conf)
	{
		ctx_printef(ctx, errno, "Couldn't init()\n");
		return 500;
	}

	/* We started and are running */
	g_conf->starttime	= time(NULL);
	g_conf->running		= true;

	/* Use the hostname as the default identity */
	gethostname(g_conf->pop_name, sizeof(g_conf->pop_name));

	/* Configure verbosity levels */
	g_conf->verbose = verbose;

	g_conf->verbose_sixxsd =
	g_conf->verbose_common =
	g_conf->verbose_config =
	g_conf->verbose_prefix =
	g_conf->verbose_ayiya =
	g_conf->verbose_thread = true;

	g_conf->debugging = 0;

	rwl_init(&g_conf->rwl_threads);
	mutex_init(g_conf->mutex_pinger);

	/* Initialize tunnels */
	tuns = &g_conf->tunnels;
	for (j=0; j < lengthof(tuns->tunnel); j++)
	{
		tun = &tuns->tunnel[j];

		/* Wipe her all out */
		memzero(tun, sizeof(*tun));

		/* Default to no type and no state */
		tun->type	= SIXXSD_TTYPE_NONE;
		tun->state	= SIXXSD_TSTATE_NONE;
		tun->debug_ctx	= NULL;

		/* Init ip_them to IPv4 any */
		/* Later we fill in the IP address with something real from AYIYA or heartbeat source */
		ipaddress_make_ipv4(&tun->ip_them, NULL);

		/* Reset statistics */
		memzero(tun->stats.traffic, sizeof(tun->stats.traffic));
		reset_latency(&tun->stats.latency);
	}

	/* Initialize subnets */
	for (i = 0; i < lengthof(g_conf->subnets); i++)
	{
		subs = &g_conf->subnets[i];
		for (j = 0; j < lengthof(subs->subnet); j++)
		{
			subs->subnet[j].tunnel_id = SIXXSD_TUNNEL_NONE;
		}
	}

	/* None yet */
	g_conf->tuntap = INVALID_SOCKET;

	return 200;
}

/* Clean our mess up */
VOID cfg_exit(VOID)
{
	if (!g_conf) return;

	/* Make sure !running is set */
	g_conf->running = false;

	rwl_destroy(&g_conf->rwl_threads);
	mutex_destroy(g_conf->mutex_pinger);

	/* Did we open syslog? Then properly close it */
	if (g_conf->opened_syslog)
	{
		mddolog("Closing Syslog\n");
		closelog();
	}

        /* Don't log anymore as these depend on g_conf ;) */
        mfree(g_conf, "g_conf", sizeof(*g_conf));
        g_conf = NULL;
}

