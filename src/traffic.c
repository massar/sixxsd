/**************************************
 SixXSd - SixXS PoP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
***************************************
 $Author: jeroen $
 $Id: traffic.c,v 1.5 2006-03-03 08:01:15 jeroen Exp $
 $Date: 2006-03-03 08:01:15 $

 SixXSd Traffic Handler
**************************************/

#include "sixxsd.h"

const char module_traffic[] = "traffic";
#define module module_traffic

void traffic_create_interface(const char *interface);
void traffic_create_interface(const char *interface)
{
	char	*args[21], filename[2048];

	args[ 0] = (char *)"create";
	args[ 1] = (char *)filename;
	args[ 2] = (char *)"-s";
	args[ 3] = (char *)"300";
	args[ 4] = (char *)"DS:inoct:COUNTER:600:0:U";
	args[ 5] = (char *)"DS:inpkt:COUNTER:600:0:U";
	args[ 6] = (char *)"DS:outoct:COUNTER:600:0:U";
	args[ 7] = (char *)"DS:outpkt:COUNTER:600:0:U";
	args[ 8] = (char *)"RRA:MIN:0.5:1:600";
	args[ 9] = (char *)"RRA:MIN:0.5:6:700";
	args[10] = (char *)"RRA:MIN:0.5:24:775";
	args[11] = (char *)"RRA:MIN:0.5:288:797";
	args[12] = (char *)"RRA:AVERAGE:0.5:1:600";
	args[13] = (char *)"RRA:AVERAGE:0.5:6:700";
	args[14] = (char *)"RRA:AVERAGE:0.5:24:775";
	args[15] = (char *)"RRA:AVERAGE:0.5:288:797";
	args[16] = (char *)"RRA:MAX:0.5:1:600";
	args[17] = (char *)"RRA:MAX:0.5:6:700";
	args[18] = (char *)"RRA:MAX:0.5:24:775";
	args[19] = (char *)"RRA:MAX:0.5:288:797";
       	args[20] = NULL;

	snprintf(filename, sizeof(filename),
		"%s/rrd/%s/traffic/%s.rrd",
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

void traffic_update_interface(const char *interface, uint64_t inoct, uint64_t outoct, uint64_t inpkt, uint64_t outpkt);
void traffic_update_interface(const char *interface, uint64_t inoct, uint64_t outoct, uint64_t inpkt, uint64_t outpkt)
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
			iface->inoct	= inoct;
			iface->outoct	= outoct;
			iface->inpkt	= inpkt;
			iface->outpkt	= outpkt;

			OS_Mutex_Release(&iface->mutex, "traffic_update_interface");
		}
	}

	args[0] = (char *)"update";
	args[1] = filename;
	args[2] = values;
	args[3] = NULL;

	snprintf(filename, sizeof(filename),
		"%s/rrd/%s/traffic/%s.rrd",
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

			/* Create traffic stats dir */
			snprintf(filename, sizeof(filename),
				"%s/rrd/%s/traffic",
				g_conf->homedir, g_conf->pop_name);
			if (mkdir(filename, 0755) != 0) return;
		}

		/* Try again */
		snprintf(filename, sizeof(filename),
			"%s/rrd/%s/traffic/%s.rrd",
			g_conf->homedir, g_conf->pop_name, interface);
			
		traffic_create_interface(interface);
	}

	snprintf(values, sizeof(values),
		"N:%llu:%llu:%llu:%llu",
		inoct, inpkt, outoct, outpkt);

	/* mddolog("Updating RRD %s with %s\n", filename, values); */

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

#ifdef _BSD
void traffic_collect(void);
void traffic_collect(void)
{
	caddr_t			ref, buf, end;
	size_t			bufsiz;
	struct if_msghdr	*ifm;
	struct sockaddr_dl	*sdl;
	struct if_data		*ifd;

	int mib[] = { CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST, 0 };

	if (sysctl(mib, sizeof(mib)/sizeof(int), NULL, &bufsiz, NULL, 0) < 0)
	{
		mdolog(LOG_ERR, "sysctl() failed: couldn't determine buffersize...\n");
		return;
	}

	ref = buf = malloc(bufsiz);
	if (!ref)
	{
		mdolog(LOG_ERR, "malloc failed...\n");
		return;
	}

	if (sysctl(mib, sizeof(mib)/sizeof(int), buf, &bufsiz, NULL, 0) < 0)
	{
		free(ref);
		mdolog(LOG_ERR, "sysctl() error...\n");
		return;
	}

	for (end = buf + bufsiz; buf < end; buf += ifm->ifm_msglen)
	{
		ifm = (struct if_msghdr *)buf;
		if (ifm->ifm_type != RTM_IFINFO) continue;

		sdl = (struct sockaddr_dl *)(ifm + 1);
		ifd = (struct if_data *)&ifm->ifm_data;

		traffic_update_interface(
			sdl->sdl_data, 
			ifd->ifi_ibytes, ifd->ifi_obytes,
			ifd->ifi_ipackets, ifd->ifi_opackets);
	}

	free(ref);
	return;
}
#endif

#ifdef _LINUX
void traffic_collect(void);
void traffic_collect(void)
{
	FILE		*f;
	uint64_t	inoct, inpkt, outoct, outpkt;
	char		dev[64];
	char		line[1024];

	f = fopen ("/proc/net/dev", "r");
	if (!f)
	{
		mdolog(LOG_ERR, "Failed to open /proc/net/dev\n");
		return;
	}

	while (fgets(line, 1024, f))
	{
		char	*p;
		int	i;

		/* Skip lines without devices */
		if (!strstr(line, ":")) continue;
		p = line;

		/* Skip leading spaces */
		while (*p && isspace(*p)) p++;

		/* Parse the device name */
		i=0;
		while (*p && *p != ':') dev[i++] = *p++;
		dev[i] = '\0';
		p++;

		/* Skip whitespace */
		while (*p && isspace (*p)) p++;

		/* Parse the Input Octets */
		inoct = atoll(p);

		/* Skip the digits of the input octets */
		while (*p && isdigit (*p)) p++;
		while (*p && isspace (*p)) p++;

		/* Parse the Input Packets */
		inpkt = atoll(p);

		/* Skip the for us unused fields */
		for (i=0; i<7; i++)
		{
			while (*p && isdigit (*p)) p++;
			while (*p && isspace (*p)) p++;
		}

		/* Parse the Output Octets */
		outoct = atoll(p);

		/* Skip the output octets */
		while (*p && isdigit (*p)) p++;
		while (*p && isspace (*p)) p++;

		/* Parse the Output Packets */
		outpkt = atoll(p);

		traffic_update_interface(dev,
			inoct, outoct,
			inpkt, outpkt);
        }
        fclose(f);

        return;
}

#endif

void *traffic_thread(void UNUSED *arg);
void *traffic_thread(void UNUSED *arg)
{
	time_t		tee;
	struct tm	teem;

	/* Show that we have started */
	mdolog(LOG_INFO, "Traffic Handler\n");

	while (g_conf && g_conf->running)
	{
		if (!g_conf->pop_name)
		{
			mdolog(LOG_WARNING, "PoP Name not configured yet, skipping collection\n");
		}
		else
		{
			/* Collect The Traffic(tm) */
			traffic_collect();
		}

		/* Get the current time */
		tee = time(NULL);
		gmtime_r(&tee, &teem);

		/* Sleep for the remaining time */
		/* and thus run every 5 mins */
		sleep(((5-(teem.tm_min % 5))*60) - teem.tm_sec);

		/*
		 * Examples of the above sleeper:
		 * 00:20:15 -> ((5-(20%5=0)=5)*60) - 15 = 5*60 - 15 = 285 = 04:45
		 * 00:20:00 -> ((5-(20%5=0)=5)*60) -  0 = 5*60 -  0 = 300 = 05:00
		 * 00:19:45 -> ((5-(19%5=4)=1)*60) - 45 = 1*60 - 45 =  15 = 00:15
		 * 00:17:15 -> ((5-(17%5=2)=3)*60) - 15 = 3*60 - 15 = 165 = 02:45
		 */
	}

	return NULL;
}

void traffic_init(void)
{
	/* Create a thread for the Traffic Statistics Handler */
	thread_add("Traffic", traffic_thread, NULL, true);
}

