/**************************************
 SixXSd - SixXS POP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
***************************************
 $Author: jeroen $
 $Id: sixxsd.c,v 1.2 2004-09-14 17:26:03 jeroen Exp $
 $Date: 2004-09-14 17:26:03 $

 SixXSd main code
**************************************/

#include "sixxsd.h"

// Configuration Variables
struct conf *g_conf = NULL;

/********************************************************************
  SixXSd Sync Management
********************************************************************/
bool sync_complete()
{
        // Walk through the complete interface & route table
	// marking sync_seen = false;

	// Sync it
	// os_sync_complete();

	// Walk through the complete interface & route table
	// if (!sync_seen)
	// {
	//	if (ignore)
	//	{
	//		remove the entry
	//	}

	return true;
}

bool init()
{
	g_conf = malloc(sizeof(struct conf));
	if (!g_conf)
	{
		dolog(LOG_ERR, "Couldn't allocate configuration memory\n");
		return false;
	}

	// Clear it, never bad, always good 
	memset(g_conf, 0, sizeof(*g_conf));

	// Initialize our configuration
#ifndef DEBUG
	g_conf->daemonize	= true;
#else
	g_conf->daemonize	= false;
#endif

	// Defaults
	g_conf->max_interfaces = 1000;
	g_conf->max_prefixes = 1000;
	g_conf->pop_tunneldevice = strdup("sixxs");

	// Initialize our counters
	g_conf->stats.starttime	= time(NULL);
	g_conf->stat_filename = strdup(SIXXSD_DUMPFILE);

	// Initialize various mutexes
	pthread_mutex_init(&g_conf->mutex, NULL);

	return true;
}

void sighup(int i)
{
	// Reset the signal
	signal(SIGHUP, &sighup);
}

void dumpstats(FILE *f)
{
	time_t			time_tee;
	unsigned int		uptime, uptime_s, uptime_m, uptime_h, uptime_d;
	char			buf[200];

	// Get the current time
	time_tee  = time(NULL);
	uptime_s  = time_tee - g_conf->stats.starttime;
	uptime_d  = uptime_s / (24*60*60);
	uptime_s -= uptime_d *  24*60*60;
	uptime_h  = uptime_s / (60*60);
	uptime_s -= uptime_h *  60*60;
	uptime_m  = uptime_s /  60;
	uptime_s -= uptime_m *  60;

	// Dump out some generic program statistics
	strftime(buf, sizeof(buf), "%Y-%m-%d %T", gmtime(&g_conf->stats.starttime));

	fprintf(f, "*** Statistics Dump\n");

	fprintf(f, "\n");

	fprintf(f, "Version              : sixxsd %s\n", SIXXSD_VERSION);
	fprintf(f, "Started              : %s GMT\n", buf);
	fprintf(f, "Uptime               : %u days %02u:%02u:%02u\n", uptime_d, uptime_h, uptime_m, uptime_s);

	fprintf(f, "\n");

	fprintf(f, "*** Statistics Dump (end)\n");
}

// Dump the statistical information
void sigusr1(int i)
{
	// Rewind the file to the start
	rewind(g_conf->stat_file);

	// Truncate the file
	ftruncate(fileno(g_conf->stat_file), (off_t)0);

	// Dump the stats
	dumpstats(g_conf->stat_file);

	// Flush the information to disk
	fflush(g_conf->stat_file);

	dolog(LOG_INFO, "Dumped statistics into %s\n", g_conf->stat_filename);

	// Reset the signal
	signal(SIGUSR1, &sigusr1);
}

// Long options
static struct option const long_options[] = {
	{"daemonize",	no_argument,		NULL, 'd'},
	{"nodaemonize",	no_argument,		NULL, 0},
	{"statsfile",	required_argument,	NULL, 0},
	{NULL,		0, NULL, 0},
};

int parse_arguments(int argc, char *argv[])
{
	int			i, option_index = 0;
	struct passwd		*passwd;

	// Handle arguments
	while ((i = getopt_long(argc, argv, "d", long_options, &option_index)) != EOF)
	{
		switch (i)
		{
		case 0:	// Long option
			if (strcmp(long_options[option_index].name, "nodaemonize") == 0)
			{
				g_conf->daemonize = false;
			}
			else if (strcmp(long_options[option_index].name, "statsfile") == 0)
			{
				if (g_conf->stat_filename) free(g_conf->stat_filename);
				g_conf->stat_filename = strdup(optarg);
				if (!g_conf->stat_filename)
				{
					dolog(LOG_ERR, "Couldn't allocate memory for statsfilename\n");
					return false;
				}
			}
			break;

		case 'd': // background
			g_conf->daemonize = true;
			break;

		default: // Default to help for all unknown arguments
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
				"\n"
				"Report bugs to Jeroen Massar <jeroen@sixxs.net>.\n",
				argv[0]);
			return false;
		}
	}
	return true;
}

int main(int argc, char *argv[], char *envp[])
{
	// Show our version in the startup logs
	dolog(LOG_INFO, "SixXSd (SixXS POP Daemon) %s by Jeroen Massar <jeroen@sixxs.net>\n", SIXXSD_VERSION);

	if (	!init() ||
		!parse_arguments(argc,argv)) return -1;

	dolog(LOG_INFO, "Max Interfaces = %u (%u bytes), Max Prefix = %u (%u bytes)\n",
		g_conf->max_interfaces,	g_conf->max_interfaces * sizeof(struct sixxs_interface),
		g_conf->max_prefixes,	g_conf->max_prefixes * sizeof(struct sixxs_prefix));

	// Allocate memory for our interfaces and prefixes
	g_conf->interfaces	= malloc(g_conf->max_interfaces * sizeof(struct sixxs_interface));
	g_conf->prefixes	= malloc(g_conf->max_prefixes * sizeof(struct sixxs_prefix));

	if (!g_conf->interfaces || !g_conf->prefixes)
	{
		dolog(LOG_ERR, "Couldn't allocated memory for interfaces or prefixes");
		return false;
	}
	memset(g_conf->interfaces, 0, sizeof(g_conf->interfaces));
	memset(g_conf->prefixes, 0, sizeof(g_conf->prefixes));
	
	// Daemonize
	if (g_conf->daemonize)
	{
		int i = fork();
		if (i < 0)
		{
			fprintf(stderr, "Couldn't fork\n");
			return -1;
		}
		// Exit the mother fork
		if (i != 0) return 0;

		// Child fork
		setsid();
		// Cleanup stdin/out/err
		freopen("/dev/null","r",stdin);
		freopen("/dev/null","w",stdout);
		freopen("/dev/null","w",stderr);
	}

	// Handle a SIGHUP to reload the config
	signal(SIGHUP, &sighup);

	// Handle SIGTERM/INT/KILL to cleanup the pid file and exit
	signal(SIGTERM,	&cleanpid);
	signal(SIGINT,	&cleanpid);
	signal(SIGKILL,	&cleanpid);

	// Dump operations
	signal(SIGUSR1,	&sigusr1);

	signal(SIGUSR2, SIG_IGN);

	// Save our PID
	savepid();

	// Open our dump file
	g_conf->stat_file = fopen(g_conf->stat_filename, "w");
	if (!g_conf->stat_file)
	{
		dolog(LOG_ERR, "Couldn't open dumpfile %s\n", g_conf->stat_filename);
		return -1;
	}
	
	// Read the former configuration file, bootstrapping this server
	cfg_fromfile("/etc/sixxsd.conf");

	g_conf->running = 1;

	// Init the OS interface
	os_init();

	// Create a thread for the Configuration Handler
//DIS	thread_add("Cfg", cfg_thread, NULL);

	// Create a thread for the Heartbeat Handler
//DIS	thread_add("HB", hb_thread, NULL);

	// Create a thread for the AYYYA Handler
	thread_add("AYIYA", ayiya_thread, NULL);

	// Create a thread for the Statistics Handler
//DIS	thread_add("Traffic", traffic_thread, NULL);

	// Do a complete_sync() every hour
	while (1)
	{
		sleep(60*60);
		// sync_complete();
	}

	// Not reached - cleanpid does the kill
	return 0;
}

