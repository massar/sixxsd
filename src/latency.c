/**************************************
 SixXSd - SixXS PoP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
***************************************
 $Author: jeroen $
 $Id: latency.c,v 1.1 2006-07-23 18:41:35 jeroen Exp $
 $Date: 2006-07-23 18:41:35 $

 SixXSd Latency Handler
**************************************/

#include "sixxsd.h"

const char module_latency[] = "latency";
#define module module_latency

void latency_create_interface(const char *interface);
void latency_create_interface(const char *interface)
{
	char	*args[20], filename[2048];

	args[ 0] = (char *)"create",
	args[ 1] = (char *)filename;
	args[ 2] = (char *)"-s";
	args[ 3] = (char *)"3600";
	args[ 4] = (char *)"DS:latency:GAUGE:7200:0:U";
	args[ 5] = (char *)"DS:loss:GAUGE:7200:0:U";
	args[ 6] = (char *)"RRA:MIN:0.5:1:600";
	args[ 7] = (char *)"RRA:MIN:0.5:6:700";
	args[ 8] = (char *)"RRA:MIN:0.5:24:775";
	args[ 9] = (char *)"RRA:MIN:0.5:288:797";
	args[10] = (char *)"RRA:AVERAGE:0.5:1:600";
	args[11] = (char *)"RRA:AVERAGE:0.5:6:700";
	args[12] = (char *)"RRA:AVERAGE:0.5:24:775";
	args[13] = (char *)"RRA:AVERAGE:0.5:288:797";
	args[14] = (char *)"RRA:MAX:0.5:1:600";
	args[15] = (char *)"RRA:MAX:0.5:6:700";
	args[16] = (char *)"RRA:MAX:0.5:24:775";
	args[17] = (char *)"RRA:MAX:0.5:288:797";
	args[18] = (char *)"\n";
	args[19] = NULL;

	snprintf(filename, sizeof(filename),
		"%s/rrd/%s/latency/%s.rrd",
		g_conf->homedir, g_conf->pop_name, interface);

	mddolog("Creating RRD for %s\n", filename);

	rrd_clear_error();
	rrd_create((sizeof(args)/sizeof(char *))-1, args);
	if (rrd_test_error())
	{
		unsigned int i;
		mdolog(LOG_ERR, "RRD Creation error: %s\n", rrd_get_error());
		for (i=0; i<(sizeof(args)/sizeof(char *)); i++)
		{
			mdolog(LOG_ERR, "arg[%u] \"%s\"\n", i, args[i]);
		}
	}
}

void latency_update_interface(const char *interface, float latency, float loss);
void latency_update_interface(const char *interface, float latency, float loss)
{
	char			*args[4], filename[2048], values[2048];
	struct stat		stats;
	unsigned int		i = strlen(g_conf->pop_tunneldevice);
	struct sixxs_interface	*iface = NULL;

	/* It's a tunneldevice? */
	if (strncasecmp(interface, g_conf->pop_tunneldevice, i) == 0)
	{
		/* Update the in-mem interface */
		i = atoi(&interface[i]);
		iface = int_get(i);
		if (iface)
		{
			iface->latency	= latency;
			iface->loss	= loss;

			OS_Mutex_Release(&iface->mutex, "latency_update_interface");
		}
	}

	args[0] = (char *)"update";
	args[1] = filename;
	args[2] = values;
	args[3] = NULL;

	snprintf(filename, sizeof(filename),
		"%s/rrd/%s/latency/%s.rrd",
		g_conf->homedir, g_conf->pop_name, interface);

	/* Does the RRD exist? */
	if (stat(filename, &stats) != 0)
	{
		mddolog("File '%s' not found, checking for dir\n", filename);

		/* Does the RRD dir exist? */
		snprintf(filename, sizeof(filename),
			"%s/rrd",
			g_conf->homedir);

		if (stat(filename, &stats) != 0)
		{
			mddolog("Dir not found, creating dir '%s'...\n", filename);
			/* Create the directory */
			if (mkdir(filename, 0755) != 0) return;
		}

		/* Does the PoP dir exist? */
		snprintf(filename, sizeof(filename),
			"%s/rrd/%s",
			g_conf->homedir, g_conf->pop_name);

		if (stat(filename, &stats) != 0)
		{
			mddolog("Dir not found, creating dir '%s'...\n", filename);
			/* Create the directory */
			if (mkdir(filename, 0755) != 0) return;

			/* Create latency stats dir */
			snprintf(filename, sizeof(filename),
				"%s/rrd/%s/latency",
				g_conf->homedir, g_conf->pop_name);
			if (mkdir(filename, 0755) != 0) return;
		}

		/* Try again */
		snprintf(filename, sizeof(filename),
			"%s/rrd/%s/latency/%s.rrd",
			g_conf->homedir, g_conf->pop_name, interface);
			
		latency_create_interface(interface);
	}

	snprintf(values, sizeof(values),
		"N:%f:%f",
		latency, loss);

	mddolog("Updating RRD %s with %s\n", filename, values);

	rrd_clear_error();

	/*
	 * Stolen from DAPd:
	 * "kludge" to fix the "API" for rrdtool
	 */
	optind = 0;
	opterr = 0;

	rrd_update((sizeof(args)/sizeof(char *))-1, args);
	if (!rrd_test_error()) return;

	/* Log and try again */
	mdolog(LOG_ERR, "RRD Update error: %s\n", rrd_get_error());
	for (i=0; i<(sizeof(args)/sizeof(char *)); i++)
	{
		mdolog(LOG_ERR, "arg[%u]: \"%s\"\n", i, args[i]);
	}
}

void latency_collect(void);
void latency_collect(void)
{
	char cmd[1000];
	unsigned int ping_count = 20, ping_size = 56;
	
	snprintf(cmd, sizeof(cmd), "fping6 -q -c %u -b %u", ping_count, ping_size);

	/* "195.177.242.34 : xmt/rcv/%loss = 5/5/0%, min/avg/max = 2.34/2.37/2.44" */

	/* latency_update_interface("boo", 0, 100); */
        return;
}

void *latency_thread(void UNUSED *arg);
void *latency_thread(void UNUSED *arg)
{
	time_t		tee;
	struct tm	teem;

	/* Show that we have started */
	mdolog(LOG_INFO, "Latency Handler\n");

	while (g_conf && g_conf->running)
	{
		if (!g_conf->pop_name)
		{
			mdolog(LOG_WARNING, "PoP Name not configured yet, skipping collection\n");
		}
		else
		{
			/* Collect The Latency(tm) */
			latency_collect();
		}

		/* Get the current time */
		tee = time(NULL);
		gmtime_r(&tee, &teem);

		/* Sleep for the remaining time */
		/* and thus run every 15 mins */
		sleep(((15-(teem.tm_min % 15))*60) - teem.tm_sec);
	}

	return NULL;
}

void latency_init(void)
{
	/* Create a thread for the Latency Statistics Handler */
	thread_add("Latency", latency_thread, NULL, true);
}

