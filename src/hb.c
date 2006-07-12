/**************************************
 SixXSd - SixXS PoP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
***************************************
 $Author: jeroen $
 $Id: hb.c,v 1.11 2006-07-12 21:25:18 jeroen Exp $
 $Date: 2006-07-12 21:25:18 $

 SixXSd Heartbeat code
**************************************/

#include "sixxsd.h"

const char module_hb[] = "hb";
#define module module_hb

#define HEARTBEAT_PORT		"3740"
#define HEARTBEAT_TUNNEL	"HEARTBEAT TUNNEL "
#define CLOCK_OFF		120	/* The maximum time in seconds that the
					   client clock is allowed to be off, thus use ntp synced clocks :) */

void hb_log(int level, struct sockaddr_storage *ci, socklen_t cl, const char *fmt, ...);
void hb_log(int level, struct sockaddr_storage *ci, socklen_t cl, const char *fmt, ...)
{
	char	buf[1024];
	char	clienthost[NI_MAXHOST];
	char	clientservice[NI_MAXSERV];
	va_list	ap;

	/* Clear them just in case */
	memset(buf, 0, sizeof(buf));
	memset(clienthost, 0, sizeof(clienthost));
	memset(clientservice, 0, sizeof(clientservice));

	getnameinfo((struct sockaddr *)ci, cl,
		clienthost, sizeof(clienthost),
		clientservice, sizeof(clientservice),
		NI_NUMERICHOST|NI_NUMERICSERV);
	
	/* Print the host+port this is coming from */
	snprintf(buf, sizeof(buf), "[%s]:%s : ", clienthost, clientservice);

	/* Print the log message behind it */
	va_start(ap, fmt);
	vsnprintf(buf+strlen(buf), sizeof(buf)-strlen(buf), fmt, ap);
	va_end(ap);
	
	/* Actually Log it */
	mdolog(level, buf);
}

void hb_checkhb(char *buf, struct sockaddr_storage *ci, socklen_t cl);
void hb_checkhb(char *buf, struct sockaddr_storage *ci, socklen_t cl)
{
	struct MD5Context	md5;
	unsigned char		our_digest[16], *p = our_digest,
				*pnt, *pnt2, tmp[1000];
	char			*ipv6_them, *ipv4_them,
				*digest, sender[] = "sender";
	struct sixxs_interface	*iface;
	struct sixxs_prefix	*pfx;
	struct in6_addr		ipv6__them;
	int			i;
	bool			using_sender = 0;
	time_t			time_tee, datetime;
	char			clienthost[NI_MAXHOST];

	/* Clear the buffer */
	memset(clienthost, 0, sizeof(clienthost));

	/* Compare the first part, fast, safe, easy */
	if (strncmp((char *)buf, HEARTBEAT_TUNNEL, sizeof(HEARTBEAT_TUNNEL)-1) != 0)
	{
		hb_log(LOG_WARNING, ci, cl, "Unknown message received: \"%s\"\n", buf);
		return;
	}

	/* Skip over the first part */
	pnt = pnt2 = (unsigned char *)buf + sizeof(HEARTBEAT_TUNNEL) - 1;

	while (*pnt2 != '\0' && *pnt2 != ' ') pnt2++;
	if (*pnt2 == '\0')
	{
		hb_log(LOG_WARNING, ci, cl, "No IPv6 Endpoint found in \"%s\"\n", buf);
		return;
	}
	*pnt2 = '\0';
	ipv6_them = strdup((char *)pnt);
	*pnt2 = ' ';

	if (inet_pton(AF_INET6, ipv6_them, &ipv6__them) <= 0)
	{
		hb_log(LOG_WARNING, ci, cl, "Sent us an invalid IPv6 address \"%s\" in \"%s\"\n", ipv6_them, buf);
		free(ipv6_them);
		return;
	}

	pfx = pfx_get(&ipv6__them, 128);
	if (pfx)
	{
		i = pfx->interface_id;
		OS_Mutex_Release(&pfx->mutex, "hb_checkhb");
	}
	if (!pfx || !pfx->is_tunnel)
	{
		hb_log(LOG_WARNING, ci, cl, "Unknown endpoint \"%s\" in \"%s\"\n", ipv6_them, buf);
		free(ipv6_them);
		return;
	}

	/* The interface */
	iface = int_get(i);
	if (!iface) return;

	/* Get the IPv4 endpoint */
	pnt = ++pnt2;
	while (*pnt2 != '\0' && *pnt2 != ' ') pnt2++;
	if (*pnt2 == '\0')
	{
		hb_log(LOG_WARNING, ci, cl, "No IPv4 Endpoint found in \"%s\" from %s for %s\n", buf, ipv6_them);
		free(ipv6_them);
		OS_Mutex_Release(&iface->mutex, "hb_checkhb");
		return;
	}
	*pnt2 = '\0';
	ipv4_them = strdup((char *)pnt);
	*pnt2 = ' ';

	getnameinfo((struct sockaddr *)ci, cl,
		clienthost, sizeof(clienthost),
		NULL, 0, NI_NUMERICHOST|NI_NUMERICSERV);

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
			OS_Mutex_Release(&iface->mutex, "hb_checkhb");
			return;
		}
	}
	else
	{
		/* We are using the sender */
		using_sender = 1;
		/* Free this */
		free(ipv4_them);
		ipv4_them = strdup(clienthost);
	}

	/* Get the date */
	pnt = ++pnt2;
	while (*pnt2 != '\0' && *pnt2 != ' ') pnt2++;
	if (*pnt2 == '\0')
	{
		hb_log(LOG_WARNING, ci, cl, "No unixtime found in \"%s\" for %s\n", buf, ipv6_them);
		free(ipv6_them);
		free(ipv4_them);
		OS_Mutex_Release(&iface->mutex, "hb_checkhb");
		return;
	}
	*pnt2 = '\0';
	datetime = atol((char *)pnt);
	*pnt2 = ' ';

	/* Verify the date & time */
	time_tee = time(NULL);

	/* Calculate the difference */
	i = time_tee - datetime;
	if (i < 0) i = -i;

	/* We allow the senders clock to be off */
	/* This also allows for some latency */
	if (i > CLOCK_OFF)
	{
		hb_log(LOG_WARNING, ci, cl, "Time is %d seconds off for %s/%s/%u\n", i, ipv6_them, iface->name, iface->interface_id);
		free(ipv6_them);
		free(ipv4_them);
		OS_Mutex_Release(&iface->mutex, "hb_checkhb");
		return;
	}

	/* Get the digest */
	pnt = ++pnt2;
	digest = strdup((char *)pnt);

	snprintf((char *)tmp, sizeof(tmp), "%s%s %s %u %s",
		HEARTBEAT_TUNNEL,
		ipv6_them,
		(using_sender == 1 ? sender : ipv4_them),
		(unsigned int)datetime,
		iface->password);

	/* Generate a MD5 */
	MD5Init(&md5);
	MD5Update(&md5, tmp, strlen((char *)tmp));
	MD5Final(our_digest, &md5);

	pnt2 = tmp;
	/* make the digest */
	for (i = 0; i < 16; i++)
	{
		sprintf((char *)pnt2, "%02x", *p++);
		pnt2+=2;
	}
	*pnt2 = '\0';

	if (strcmp(digest, (char *)tmp) != 0)
	{
		hb_log(LOG_WARNING, ci, cl, "MD5 digests verification error: %s vs %s for %s\n", digest, tmp, ipv6_them);
		free(ipv6_them);
		free(ipv4_them);
		free(digest);
		OS_Mutex_Release(&iface->mutex, "hb_checkhb");
		return;
	}

	/* Goody, valid information, we love that */

	/* Reconfigure and mark it up */
	int_set_endpoint(iface, ((struct sockaddr_in *)ci)->sin_addr);

	/* Timestamp for marking it down in the future */
	int_beat(iface);

	free(ipv6_them);
	free(ipv4_them);
	free(digest);
	OS_Mutex_Release(&iface->mutex, "hb_checkhb");
	return;
}

void *hb_thread(void UNUSED *arg);
void *hb_thread(void UNUSED *arg)
{
	int			listenfd, n, i;
	struct sockaddr_storage	ci;
	socklen_t		cl;
	char			buf[2048];
	fd_set			readset;
	struct timeval		timeout;

	/* Show that we have started */
	mdolog(LOG_INFO, "Heartbeat Handler\n");

	if (!inet_ntop(AF_INET, &g_conf->pop_ipv4, buf, sizeof(buf)))
	{
		mdolog(LOG_ERR, "Configuration error, pop_ipv4 not set to a valid IPv4 address\n");
		return NULL;
	}

	/* Setup listening socket */
	listenfd = listen_server("hb", buf, HEARTBEAT_PORT, AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0);
	if (listenfd < 0)
	{
		mdolog(LOG_ERR, "listen_server error:: could not create listening socket\n");
		return NULL;
	}

	while (g_conf->running)
	{
		/* Timeout after 5 seconds non-activity to check if we are still running */
		FD_ZERO(&readset);
		FD_SET(listenfd, &readset);
		memset(&timeout, 0, sizeof(timeout));
		timeout.tv_sec = 5;
		n = select(listenfd+1, &readset, NULL, NULL, &timeout);

		/* Nothing happened for 5 seconds */
		if (n == 0) continue;

		/* Handle errors */
		if (n < 0)
		{
			memset(buf, 0, sizeof(buf));
			strerror_r(errno, buf, sizeof(buf));
			mdolog(LOG_ERR, "Couldn't select from Heartbeat socket: %s (%d)\n", buf, errno);
			break;
		}

		cl = sizeof(ci);
		memset(buf, 0, sizeof(buf));
		/* sizeof(buf) - 1 so we can always use the final byte as terminator :) */
		n = recvfrom(listenfd, buf, sizeof(buf)-1, 0, (struct sockaddr *)&ci, &cl);

		if (n == 0) continue;

		/* Handle errors */
		if (n < 0)
		{
			memset(buf, 0, sizeof(buf));
			strerror_r(errno, buf, sizeof(buf));
			mdolog(LOG_ERR, "Couldn't select from Heartbeat socket: %s (%d)\n", buf, errno);
			break;
		}

		/* Check if characters in buffer are valid */
		for (i=0;i<n;i++)
		{
			/* Filter newlines, handy for testing */
			/* and for building a heartbeat using nc ;) */
			if (buf[i] == 10 || buf[i] == 13)
			{
				buf[i] = 0;
				break;
			}

			/* Filter out odd chars */
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

		/* Ignore empty lines */
		if (i == 0) continue;

		hb_checkhb(buf, &ci, cl);
	}

	return NULL;
}

void hb_init(void)
{
	/* Create a thread for the Heartbeat Handler */
	thread_add("hb", hb_thread, NULL, true);
}

