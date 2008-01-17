/**************************************
 SixXSd - SixXS PoP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
***************************************
 $Author: jeroen $
 $Id: sixxsd.c,v 1.23 2008-01-17 08:18:34 jeroen Exp $
 $Date: 2008-01-17 08:18:34 $

 SixXSd main code
**************************************/

#include "sixxsd.h"

const char module_sixxsd[] = "sixxsd";
#define module module_sixxsd

/* Configuration Variables */
struct conf *g_conf = NULL;

/********************************************************************
  SixXSd Sync Management
********************************************************************/
void sync_complete()
{
	struct sixxs_interface	*iface;
	struct sixxs_prefix	*pfx;
	unsigned int		i;
	char			buf[100];

	/* Get the OS in sync */
	os_sync_complete();

	/* Check what is not synced yet */

	/* Walk through all the interfaces */
	for (i = 0; g_conf && g_conf->running && i < g_conf->max_interfaces; i++)
	{
		iface = g_conf->interfaces + i;
		if (iface->type == IFACE_UNSPEC || iface->type == IFACE_NULL) continue;

		/* Only check inconsistent interfaces */
		if (	(iface->state == IFSTATE_UP && iface->synced_link && iface->synced_addr && iface->synced_local && iface->synced_remote && iface->subnets_got == iface->subnets_up) ||
			(iface->state != IFSTATE_UP && !iface->synced_link && !iface->synced_addr && !iface->synced_local && !iface->synced_remote && iface->subnets_up == 0))
		{
			continue;
		}

		mddolog("Interface %s/%u (%s%s%s%s%s)\n",
			iface->name, iface->interface_id,
			iface->synced_link ? "I" : "i",
			iface->synced_addr ? "A" : "a",
			iface->synced_local ? "L" : "l",
			iface->synced_remote ? "R" : "r",
			iface->synced_subnet ? "S" : "s");

		if (!((iface->type == IFACE_PROTO41_HB || iface->type == IFACE_AYIYA) && iface->state == IFSTATE_DOWN))
		{
			int_set_state(iface, iface->state);
		}
	}

	for (i = 0; g_conf && g_conf->running && i < g_conf->max_prefixes; i++)
	{
		pfx = g_conf->prefixes + i;
		if (!pfx->valid || pfx->is_tunnel || pfx->synced) continue;

		inet_ntop(AF_INET6, &pfx->prefix, buf, sizeof(buf));

		iface = int_get(pfx->interface_id);
		if (!iface)
		{
			mddolog("Sync: Prefix %u %s/%u does not have a valid interface %u!?\n", i, buf, pfx->length, pfx->interface_id);
			continue;
		}

		/* Only report when the link is up */
		if (iface->synced_link)
		{
			mddolog("Sync: Prefix %u %s/%u on %s is not synced\n", i, buf, pfx->length, iface->name);

			/* Try to make it working */
			os_sync_routes(iface);
		}

		OS_Mutex_Release(&iface->mutex, "sync_complete");
	}
}

void cleandeadtunnels(void);
void cleandeadtunnels(void)
{
	struct sixxs_interface	*iface;
	unsigned int		i, t;
	time_t			time_tee;
	struct tm		teem;

	time_tee = time(NULL);
	time_tee = mktime(gmtime_r(&time_tee, &teem));

	for (i = 0; g_conf && g_conf->running && i < g_conf->max_interfaces; i++)
	{
		iface = g_conf->interfaces + i;

		/* 
		 * Dead tunnels can only happen to
		 * AYIYA and Heartbeat Tunnels which are up
		 */
		if (	iface->state != IFSTATE_UP ||
			(iface->type != IFACE_PROTO41_HB &&
			 iface->type != IFACE_AYIYA)) continue;

		OS_Mutex_Lock(&iface->mutex, "cleandeadtunnels");

		if (time_tee < iface->hb_lastbeat) t = 4242;
		else t = time_tee - iface->hb_lastbeat;

		/* Didn't see it? */
		if (t > (g_conf->pop_hb_timeout*2))
		{
			/* Down you go */
			mddolog("Marking %s down due to heartbeat timeout (%u/%u)\n",
				iface->name, t, g_conf->pop_hb_timeout);
			int_set_state(iface, IFSTATE_DOWN);
		}

		OS_Mutex_Release(&iface->mutex, "cleandeadtunnels");
	}
}

void cleanup(void);
void cleanup(void)
{
	struct sixxs_pop_prefix *pp, *pp2;

	thread_cleanup();

	/* Free interfaces & prefixes */
	if (g_conf->interfaces)		free(g_conf->interfaces);
	if (g_conf->prefixes)		free(g_conf->prefixes);
	if (g_conf->pop_name)		free(g_conf->pop_name);
	if (g_conf->pop_tunneldevice)	free(g_conf->pop_tunneldevice);
	if (g_conf->pop_ignoredevices)	free(g_conf->pop_ignoredevices);
	if (g_conf->pop_tinc_device)	free(g_conf->pop_tinc_device);
	if (g_conf->pop_tinc_config)	free(g_conf->pop_tinc_config);
	if (g_conf->homedir) free(g_conf->homedir);

	for (pp = g_conf->pop_prefixes; pp; pp = pp2)
	{
		pp2 = pp->next;
		free(pp);
	}

	/* Initialize various mutexes */
	OS_Mutex_Destroy(&g_conf->mutex_thread);
	OS_Mutex_Destroy(&g_conf->mutex_interfaces);
	OS_Mutex_Destroy(&g_conf->mutex_prefixes);
	OS_Mutex_Destroy(&g_conf->mutex_pop_prefixes);
	OS_Mutex_Destroy(&g_conf->mutex_log);

	/* Free the config memory */
	free(g_conf);
}

bool init(void);
bool init(void)
{
	g_conf = malloc(sizeof(struct conf));
	if (!g_conf)
	{
		mdolog(LOG_ERR, "Couldn't allocate configuration memory\n");
		return false;
	}

	/* Clear it, never bad, always good */ 
	memset(g_conf, 0, sizeof(*g_conf));

	/* Initialize our configuration */
	g_conf->starttime		= time(NULL);

	
#ifndef DEBUG
	g_conf->daemonize		= true;
	g_conf->verbose			= 0;
#else
	g_conf->daemonize		= false;
	g_conf->verbose			= 0;
#endif

	/* Don't sync yet as we are not configured */
	g_conf->do_sync			= false;

	/* Defaults */
	g_conf->max_interfaces		= 1024*4;
	g_conf->max_prefixes		= 1024*64;
	g_conf->pop_tunneldevice	= strdup("sixxs");

	g_conf->homedir			= strdup("/home/sixxs");

	/* Initialize our counters */
	g_conf->stats.starttime		= time(NULL);

	/* Initialize various mutexes */
	OS_Mutex_Init(&g_conf->mutex_thread);
	OS_Mutex_Init(&g_conf->mutex_interfaces);
	OS_Mutex_Init(&g_conf->mutex_prefixes);
	OS_Mutex_Init(&g_conf->mutex_pop_prefixes);
	OS_Mutex_Init(&g_conf->mutex_log);

	/* We are running */
	g_conf->running = true;

	return true;
}

void sighup(int i);
void sighup(int i)
{
	/* Ignore the signal */
	signal(i, SIG_IGN);

	/* Load configuration */
	cfg_fromfile("/home/sixxs/sixxsd.conf");

	/* Synchronize it */
	sync_complete();

	/* Reset the signal */
	signal(i, &sighup);
}

void welcome(void);
void welcome(void)
{
	/* Show our version in the startup logs */
	mdolog(LOG_INFO, "SixXSd (SixXS PoP Daemon) %s by Jeroen Massar <jeroen@sixxs.net>\n", SIXXSD_VERSION);
	mdolog(LOG_INFO, "%s\n", BUILDINFO);
}

/* Long options */
static struct option const long_options[] = {
	{"daemonize",	no_argument,		NULL, 'd'},
	{"foreground",	no_argument,		NULL, 'f'},
	{"logfile",	required_argument,	NULL, 'l'},
	{"verbose",	no_argument,		NULL, 'v'},
	{"verbosity",	required_argument,	NULL, 'Y'},
	{"version",	no_argument,		NULL, 'V'},
	{NULL,		0, NULL, 0},
};

static const char long_opts[] = "dfl:vY:V";

int parse_arguments(int argc, char *argv[]);
int parse_arguments(int argc, char *argv[])
{
	int i, option_index = 0;

	/* Handle arguments */
	while ((i = getopt_long(argc, argv, long_opts, long_options, &option_index)) != EOF)
	{
		switch (i)
		{
		case 0:	/* Long option */
			break;

		case 'd': /* background */
			g_conf->daemonize = true;
			break;

		case 'f': /* foreground */
			g_conf->daemonize = false;
			break;

		case 'l': /* logfile */
			openlogfile(optarg);
			break;

		case 'v': /* verbose */
			g_conf->verbose++;
			break;

		case 'Y': /* verbosity */
			g_conf->verbose = atoi(optarg);
			break;

		case 'V': /* version */
			welcome();
			return false;

		default: /* Default to help for all unknown arguments */
			fprintf(stderr,
				"%s [opts]\n"
				"\n"
				"-d, --daemonize            daemonize"
#ifndef DEBUG
				" (default)"
#endif
				"\n"
				"    --nodaemonize          don't daemonize"
#ifdef DEBUG
				" (default)"
#endif
				"\n"
				"-l  --logfile <filename>   Name of the file to use for logging\n"
				"-v  --verbose              Verbose mode (multiple to make higher)\n"
				"-Y  --verbosity <x>        Directly set verbosity level\n"
				"-V  --version              Show version and exit\n"
				"\n"
				"Report bugs to Jeroen Massar <jeroen@sixxs.net>.\n",
				argv[0]);
			return false;
		}
	}
	return true;
}

#ifndef _WIN32
int main(int argc, char *argv[], char UNUSED *envp[]);
int main(int argc, char *argv[], char UNUSED *envp[])
#else
int sixxsd_main(int argc, char *argv[], char UNUSED *envp[]);
int sixxsd_main(int argc, char *argv[], char UNUSED *envp[])
#endif
{
	unsigned int loops = 0, i;

	if (	!init() ||
		!parse_arguments(argc,argv)) return -1;

	welcome();

	mdolog(LOG_INFO, "Max Interfaces = %u x %u (%u bytes), Max Prefix = %u x %u (%u bytes)\n",
		g_conf->max_interfaces,	sizeof(struct sixxs_interface),
		g_conf->max_interfaces * sizeof(struct sixxs_interface),
		g_conf->max_prefixes, sizeof(struct sixxs_prefix),
		g_conf->max_prefixes * sizeof(struct sixxs_prefix));

	/* Allocate memory for our interfaces and prefixes */
	g_conf->interfaces	= malloc(g_conf->max_interfaces * sizeof(struct sixxs_interface));
	g_conf->prefixes	= malloc(g_conf->max_prefixes * sizeof(struct sixxs_prefix));

	if (!g_conf->interfaces || !g_conf->prefixes)
	{
		mdolog(LOG_ERR, "Couldn't allocate memory for interfaces or prefixes");
		return false;
	}

	memset(g_conf->interfaces, 0, g_conf->max_interfaces * sizeof(struct sixxs_interface));
	memset(g_conf->prefixes, 0, g_conf->max_prefixes * sizeof(struct sixxs_prefix));

	/* Init */
	for (i=0; i < g_conf->max_interfaces; i++)
	{
		g_conf->interfaces[i].type = IFACE_UNSPEC;
		g_conf->interfaces[i].ayiya_fd = -1;
	}

	/* Initialize the NULL interface */
	strncpy(g_conf->interfaces[0].name, "null0", 5);
	g_conf->interfaces[0].type = IFACE_NULL;
	g_conf->interfaces[0].state = IFSTATE_UP;
	g_conf->interfaces[0].synced_link = true;
	g_conf->interfaces[0].synced_addr = true;
	g_conf->interfaces[0].synced_local = true;
	g_conf->interfaces[0].synced_remote = true;

	/* Daemonize */
	if (g_conf->daemonize)
	{
		int j = fork();
		if (j < 0)
		{
			fprintf(stderr, "Couldn't fork\n");
			return -1;
		}
		/* Exit the mother fork */
		if (j != 0) return 0;

		/* Child fork */
		setsid();
		/* Cleanup stdin/out/err */
		freopen("/dev/null","r",stdin);
		freopen("/dev/null","w",stdout);
		freopen("/dev/null","w",stderr);
	}

	/* Handle a SIGHUP to reload the config */
	signal(SIGHUP, &sighup);

	/* Ignore SIGTERM/INT/KILL */
	signal(SIGTERM,	SIG_IGN);
	signal(SIGINT,	SIG_IGN);
	signal(SIGKILL,	SIG_IGN);

	signal(SIGUSR1,	SIG_IGN);
	signal(SIGUSR2, SIG_IGN);

	/* Read the former configuration file, bootstrapping this server */
	cfg_fromfile("/home/sixxs/sixxsd.conf");

	/* Start OS update handling */
	os_init();

	/* Configuration will now match the OS state */
	sync_complete();

	/* Start doing syncs now we have at least an initial configuration file */
	g_conf->do_sync = true;

	/* Fill in the missing bits */
	sync_complete();

	/* Allow reconfiguration etc */
	cfg_init();
	ayiya_init();
	hb_init();
	traffic_init();
	latency_init();

	/* Idle loop */
	while (g_conf->running)
	{
		cleandeadtunnels();
		sleep(10);
		loops++;
		loops%=360;

		if (loops == 0) sync_complete();
	}

	/* Show the message in the log */
	mdolog(LOG_INFO, "Shutdown; Thank you for using SixXSd\n");

	/* Cleanup g_conf */
	cleanup();

	return 0;
}

