/**************************************
 SixXSd - SixXS POP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
***************************************
 $Author: jeroen $
 $Id: hb.c,v 1.2 2005-01-31 17:06:26 jeroen Exp $
 $Date: 2005-01-31 17:06:26 $

 SixXSd Heartbeat code
**************************************/

// TODO: Clean dead tunnels

#include "sixxsd.h"

#define HEARTBEAT_PORT		"3740"
#define HEARTBEAT_TUNNEL	"HEARTBEAT TUNNEL "
#define CLOCK_OFF		120	// The maximum time in seconds that the
					// client clock is allowed to be off, thus use ntp synced clocks :)

void hb_log(int level, struct sockaddr_storage *ci, socklen_t cl, char *fmt, ...)
{
	char buf[1024];
	char clienthost[NI_MAXHOST];
	char clientservice[NI_MAXSERV];

	// Clear them just in case
	memset(buf, 0, sizeof(buf));
	memset(clienthost, 0, sizeof(clienthost));
	memset(clientservice, 0, sizeof(clientservice));

	getnameinfo((struct sockaddr *)ci, cl,
		clienthost, sizeof(clienthost),
		clientservice, sizeof(clientservice),
		NI_NUMERICHOST);
	
	// Print the host+port this is coming from
	snprintf(buf, sizeof(buf), "[HB] [%s]:%s : ", clienthost, clientservice);

	// Print the log message behind it
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf+strlen(buf), sizeof(buf)-strlen(buf), fmt, ap);
	va_end(ap);
	
	// Actually Log it
	dolog(level, buf);
}

void hb_checkhb(char *buf, struct sockaddr_storage *ci, socklen_t cl)
{
	struct MD5Context	md5;
	unsigned char		our_digest[16], *p = our_digest,
				*pnt, *pnt2, tmp[1000],
				*ipv6_them, *ipv4_them,
				*digest, sender[] = "sender";
	struct sixxs_interface	*iface;
	struct sixxs_prefix	*pfx;
	struct in_addr		ipv4__them;
	struct in6_addr		ipv6__them;
	int			i;
	bool			using_sender = 0;
	time_t			time_tee, datetime;
	char			clienthost[NI_MAXHOST];

	// Clear the buffer
	memset(clienthost, 0, sizeof(clienthost));

	// Compare the first part, fast, safe, easy
	if (strncmp(buf, HEARTBEAT_TUNNEL, sizeof(HEARTBEAT_TUNNEL)-1) != 0)
	{
		hb_log(LOG_WARNING, ci, cl, "Unknown message received: \"%s\"\n", buf);
		return;
	}

	// Skip over the first part
	pnt = pnt2 = buf + sizeof(HEARTBEAT_TUNNEL) - 1;

	while (*pnt2 != '\0' && *pnt2 != ' ') *pnt2++;
	if (*pnt2 == '\0')
	{
		hb_log(LOG_WARNING, ci, cl, "No IPv6 Endpoint found in \"%s\"\n", buf);
		return;
	}
	*pnt2 = '\0';
	ipv6_them = strdup(pnt);
	*pnt2 = ' ';

	if (inet_pton(AF_INET6, ipv6_them, &ipv6__them) <= 0)
	{
		hb_log(LOG_WARNING, ci, cl, "Sent us an invalid IPv6 address \"%s\" in \"%s\"\n", ipv6_them, buf);
		free(ipv6_them);
		return;
	}

	pfx = pfx_get(&ipv6__them, 128);
	if (!pfx || !pfx->is_tunnel)
	{
		hb_log(LOG_WARNING, ci, cl, "Unknown endpoint \"%s\" in \"%s\"\n", ipv6_them, buf);
		free(ipv6_them);
		return;
	}

	// The interface
	iface = int_get(pfx->interface_id);
	if (!iface) return;

	// Get the IPv4 endpoint
	pnt = ++pnt2;
	while (*pnt2 != '\0' && *pnt2 != ' ') *pnt2++;
	if (*pnt2 == '\0')
	{
		hb_log(LOG_WARNING, ci, cl, "No IPv4 Endpoint found in \"%s\" from %s for %s\n", buf, ipv6_them);
		free(ipv6_them);
		return;
	}
	*pnt2 = '\0';
	ipv4_them = strdup(pnt);
	*pnt2 = ' ';

	getnameinfo((struct sockaddr *)ci, cl,
		clienthost, sizeof(clienthost),
		NULL, 0, NI_NUMERICHOST);

	/* Does the packet specify that we should check the sender address? */
	if (strcmp(ipv4_them, sender) != 0)
	{
		if (strcmp(ipv4_them, clienthost) != 0)
		{
			hb_log(LOG_WARNING, ci, cl,
				"Message IPv4 %s doesn't match with the sender's IPv4 for %s\n",
				ipv4_them, ipv6_them);
			free(ipv6_them);
			free(ipv4_them);
				return;
		}
	}
	else
	{
		// We are using the sender
		using_sender = 1;
		// Free this
		free(ipv4_them);
		ipv4_them = strdup(clienthost);
	}

	// Get the date
	pnt = ++pnt2;
	while (*pnt2 != '\0' && *pnt2 != ' ') *pnt2++;
	if (*pnt2 == '\0')
	{
		hb_log(LOG_WARNING, ci, cl, "No unixtime found in \"%s\" for %s\n", buf, ipv6_them);
		free(ipv6_them);
		free(ipv4_them);
		return;
	}
	*pnt2 = '\0';
	datetime = atol(pnt);
	*pnt2 = ' ';

	// Verify the date & time
	time_tee = time(NULL);

	// Calculate the difference
	i = time_tee - datetime;
	if (i < 0) i = -i;

	// We allow the senders clock to be off
	// This also allows for some latency
	if (i > CLOCK_OFF)
	{
		hb_log(LOG_WARNING, ci, cl, "Time is %d seconds off for %s\n", i, ipv6_them);
		free(ipv6_them);
		free(ipv4_them);
		return;
	}

	// Get the digest
	pnt = ++pnt2;
	digest = strdup(pnt);

	snprintf(tmp, sizeof(tmp), "%s%s %s %ld %s",
		HEARTBEAT_TUNNEL,
		ipv6_them,
		(using_sender == 1 ? sender : ipv4_them),
		datetime,
		iface->hb_password);

	// Generate a MD5
	MD5Init(&md5);
	MD5Update(&md5, tmp, strlen(tmp));
	MD5Final(our_digest, &md5);

	pnt2 = tmp;
	// make the digest
	for (i = 0; i < 16; i++)
	{
		sprintf(pnt2, "%02x", *p++);
		pnt2+=2;
	}
	*pnt2 = '\0';

	if (strcmp(digest, tmp) != 0)
	{
		hb_log(LOG_WARNING, ci, cl, "MD5 digests verification error: %s vs %s for %s\n", digest, tmp, ipv6_them);
		free(ipv6_them);
		free(ipv4_them);
		free(digest);
		return;
	}

	// Goody, valid information, we love that

	// Don't log these, there will be a lot :)
	// D(hb_log(LOG_DEBUG, ci, cl, "Sent an update for %s\n", ipv6_them);)
	int_beat(iface);

	// Reconfigure
	int_set_endpoint(iface, ipv4__them);

	free(ipv6_them);
	free(ipv4_them);
	free(digest);
	return;
}

void *hb_thread(void *arg)
{
	int			listenfd, n, i;
	struct sockaddr_storage	ci;
	socklen_t		cl;
	char			buf[2048];

	// Show that we have started
	dolog(LOG_INFO, "[HB] Heartbeat Handler\n");

	if (!inet_ntop(AF_INET, &g_conf->pop_ipv4, buf, sizeof(buf)))
	{
		dolog(LOG_ERR, "[HB] Configuration error, pop_ipv4 not set to a valid IPv4 address\n");
		return NULL;
	}

	/* Setup listening socket */
	listenfd = listen_server("HB", buf, HEARTBEAT_PORT, AF_INET, SOCK_DGRAM);
	if (listenfd < 0)
	{
		dolog(LOG_ERR, "[HB] listen_server error:: could not create listening socket\n");
		return NULL;
	}

	while (g_conf->running)
	{
		cl = sizeof(ci);
		memset(buf, 0, sizeof(buf));
		// sizeof(buf) - 1 so we can always use the final byte as terminator :)
		n = recvfrom(listenfd, buf, sizeof(buf)-1, 0, (struct sockaddr *)&ci, &cl);

		if (n < 0) continue;

		// Check if characters in buffer are valid
		for (i=0;i<n;i++)
		{
			// Filter newlines, handy for testing
			// and for building a heartbeat using nc ;)
			if (buf[i] == 10 || buf[i] == 13)
			{
				buf[i] = 0;
				break;
			}

			// Filter out odd chars
			if (!(  (buf[i] >= 'a' && buf[i] <= 'z') ||
				(buf[i] >= 'A' && buf[i] <= 'Z') ||
				(buf[i] >= '0' && buf[i] <= '9') ||
				 buf[i] != ' ' ||
				 buf[i] != ':' ||
				 buf[i] != '.'
				))
			{
				buf[i] = 0;
				hb_log(LOG_WARNING, &ci, cl,
					"ignoring due to odd chars after \"%s\"\n", buf);
				i = 0;
				break;
			}
		}

		// Ignore empty lines
		if (i == 0) continue;

		hb_checkhb(buf, &ci, cl);
	}

	return NULL;
}
