/**************************************
 SixXSd - SixXS PoP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
***************************************
 $Author: jeroen $
 $Id: sixxsd.c,v 1.8 2006-02-22 16:05:12 jeroen Exp $
 $Date: 2006-02-22 16:05:12 $

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
		if (iface->type == IFACE_UNSPEC) continue;

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

		printf("Prefix %u %s/%u is not synced\n", i, buf, pfx->length);
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

	/* Close files and sockets */
	fclose(g_conf->stat_file);
	free(g_conf->stat_filename);

	/* Free interfaces & prefixes */
	if (g_conf->interfaces)		free(g_conf->interfaces);
	if (g_conf->prefixes)		free(g_conf->prefixes);
	if (g_conf->pop_name)		free(g_conf->pop_name);
	if (g_conf->pop_tunneldevice)	free(g_conf->pop_tunneldevice);
	if (g_conf->pop_ignoredevices)	free(g_conf->pop_ignoredevices);
	if (g_conf->pop_tinc_device)	free(g_conf->pop_tinc_device);
	if (g_conf->pop_tinc_config)	free(g_conf->pop_tinc_config);

	for (pp = g_conf->pop_prefixes; pp; pp = pp2)
	{
		pp2 = pp->next;
		free(pp);
	}

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
#ifndef DEBUG
	g_conf->daemonize		= true;
	g_conf->verbose			= 0;
#else
	g_conf->daemonize		= false;
	g_conf->verbose			= 3;
#endif

	/* Don't sync yet as we are not configured */
	g_conf->do_sync			= false;

	/* Defaults */
	g_conf->max_interfaces		= 4000;
	g_conf->max_prefixes		= 4000;
	g_conf->pop_tunneldevice	= strdup("sixxs");

	g_conf->homedir			= strdup("/home/sixxs");

	/* Initialize our counters */
	g_conf->stats.starttime		= time(NULL);
	g_conf->stat_filename		= strdup(SIXXSD_DUMPFILE);

	/* Initialize various mutexes */
	OS_Mutex_Init(&g_conf->mutex);
	OS_Mutex_Init(&g_conf->mutex_thread);
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

void dumpstats(FILE *f);
void dumpstats(FILE *f)
{
	time_t			time_tee;
	unsigned int		uptime_s, uptime_m, uptime_h, uptime_d;
	char			buf[200];

	/* Get the current time */
	time_tee  = time(NULL);
	uptime_s  = time_tee - g_conf->stats.starttime;
	uptime_d  = uptime_s / (24*60*60);
	uptime_s -= uptime_d *  24*60*60;
	uptime_h  = uptime_s / (60*60);
	uptime_s -= uptime_h *  60*60;
	uptime_m  = uptime_s /  60;
	uptime_s -= uptime_m *  60;

	/* Dump out some generic program statistics */
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", gmtime(&g_conf->stats.starttime));

	fprintf(f, "*** Statistics Dump\n");

	fprintf(f, "\n");

	fprintf(f, "Version              : sixxsd %s\n", SIXXSD_VERSION);
	fprintf(f, "Started              : %s GMT\n", buf);
	fprintf(f, "Uptime               : %u days %02u:%02u:%02u\n", uptime_d, uptime_h, uptime_m, uptime_s);

	fprintf(f, "\n");

	fprintf(f, "*** Statistics Dump (end)\n");
}

/* Dump the statistical information */
void sigusr1(int i);
void sigusr1(int i)
{
	/* Ignore the signal */
	signal(i, SIG_IGN);

	/* Rewind the file to the start */
	rewind(g_conf->stat_file);

	/* Truncate the file */
	ftruncate(fileno(g_conf->stat_file), (off_t)0);

	/* Dump the stats */
	dumpstats(g_conf->stat_file);

	/* Flush the information to disk */
	fflush(g_conf->stat_file);

	mdolog(LOG_INFO, "Dumped statistics into %s\n", g_conf->stat_filename);

	/* Reset the signal */
	signal(i, &sigusr1);
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
	{"verbose",	no_argument,		NULL, 'v'},
	{"verbosity",	required_argument,	NULL, 'Y'},
	{"version",	no_argument,		NULL, 'V'},
	{"statsfile",	required_argument,	NULL, 0},
	{NULL,		0, NULL, 0},
};

static const char long_opts[] = "dfvYV";

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
			if (strcmp(long_options[option_index].name, "statsfile") == 0)
			{
				if (g_conf->stat_filename) free(g_conf->stat_filename);
				g_conf->stat_filename = strdup(optarg);
				if (!g_conf->stat_filename)
				{
					mdolog(LOG_ERR, "Couldn't allocate memory for statsfilename\n");
					return false;
				}
			}
			break;

		case 'd': /* background */
			g_conf->daemonize = true;
			break;

		case 'f': /* foreground */
			g_conf->daemonize = false;
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
				"    --statsfile <filename> Name of the file to dump stats into\n"
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
	unsigned int loops = 0;

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
	
	/* Daemonize */
	if (g_conf->daemonize)
	{
		int i = fork();
		if (i < 0)
		{
			fprintf(stderr, "Couldn't fork\n");
			return -1;
		}
		/* Exit the mother fork */
		if (i != 0) return 0;

		/* Child fork */
		setsid();
		/* Cleanup stdin/out/err */
		freopen("/dev/null","r",stdin);
		freopen("/dev/null","w",stdout);
		freopen("/dev/null","w",stderr);
	}

	/* Handle a SIGHUP to reload the config */
	signal(SIGHUP, &sighup);

	/* Handle SIGTERM/INT/KILL to cleanup the pid file and exit */
	signal(SIGTERM,	&cleanpid);
	signal(SIGINT,	&cleanpid);
	signal(SIGKILL,	&cleanpid);

	/* Dump operations */
	signal(SIGUSR1,	&sigusr1);

	signal(SIGUSR2, SIG_IGN);

	/* Save our PID */
	savepid();

	/* Open our dump file */
	g_conf->stat_file = fopen(g_conf->stat_filename, "w");
	if (!g_conf->stat_file)
	{
		mdolog(LOG_ERR, "Couldn't open dumpfile %s\n", g_conf->stat_filename);
		return -1;
	}
	
	/* Read the former configuration file, bootstrapping this server */
	cfg_fromfile("/home/sixxs/sixxsd.conf");

	/* Start doing syncs now we have at least an initial configuration file */
	g_conf->do_sync = true;

	/* Start OS update handling */
	os_init();

	/* Configuration will now match the OS state */
	sync_complete();

#ifdef DEBUG
	mddolog("SYNC CHECK\n");
	sync_complete();
	mddolog("SYNC CHECK - end\n");
#endif

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

