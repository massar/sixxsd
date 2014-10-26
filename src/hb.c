/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2013 All Rights Reserved
************************************************************
 Heartbeat
***********************************************************/
#include "sixxsd.h"

const char module_hb[] = "hb";
#define module module_hb

static const char hb_prefix[] = "HEARTBEAT TUNNEL ";

static VOID hb_log(int level, const IPADDRESS *src, const char *ATTR_RESTRICT fmt, ...) ATTR_FORMAT(printf, 3, 4);
static VOID hb_log(int level, const IPADDRESS *src, const char *fmt, ...)
{
	char	buf[1024];
	char	srca[NI_MAXHOST];
	va_list	ap;

	inet_ntopA(src, srca, sizeof(srca));

	/* Print the log message behind it */
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	
	/* Actually Log it */
	mdolog(level, "[%s]: %s", srca, buf);
}

VOID hb_in(const IPADDRESS *src, const uint8_t *packet, uint32_t len)
{
	struct MD5Context	md5;
	struct sixxsd_tunnel	*tun;
	uint16_t		in_tid;
	uint8_t			message[256], our_digest[16], tmp[1024], *p = our_digest;
	char			them[64], sender[64], *pnt, *pnt2;
	IPADDRESS		identity, ip;
	int64_t			i;
	uint64_t		currtime, datetime;
	BOOL			is_tunnel;

	if (len >= sizeof(message))
	{
		hb_log(LOG_WARNING, src, "incoming: message to long (%u>%u)\n", len, (unsigned int)sizeof(message));
		return;
	}

	/* Copy it into a temporary buffer we can modify */
	memcpy(message, packet, len);
	/* Terminate it for sure */
	message[len] = '\0';
	len--;

	/* Trim off any \r or \n's */
	while (len > 0 && (message[len] == '\r' || message[len] == '\n'))
	{
		message[len] = '\0';
		len--;
	}

	/* Compare the first part, fast, safe, easy */
	if (strncmp((char *)packet, hb_prefix, sizeof(hb_prefix)-1) != 0)
	{
		hb_log(LOG_WARNING, src, "incoming: Unknown message received: \"%s\"\n", message);
		return;
	}

	/* Skip over the first part */
	pnt = pnt2 = (char *)&message[sizeof(hb_prefix) - 1];

	while (*pnt2 != '\0' && *pnt2 != ' ') pnt2++;
	if (*pnt2 == '\0')
	{
		hb_log(LOG_WARNING, src, "incoming: No Endpoint found in \"%s\"\n", message);
		return;
	}
	*pnt2 = '\0';

	/* XXX: Handle IPv6->IPv4 heartbeats, now IPv4->IPv6 only */
	if (inet_pton(AF_INET6, (char *)pnt, &identity) <= 0)
	{
		*pnt2 = ' ';
		hb_log(LOG_WARNING, src, "incoming: Invalid IPv6 address in \"%s\"\n", message);
		return;
	}

	strncpy(them, pnt, sizeof(them));

	*pnt2 = ' ';

	/* Heartbeat identity is always IPv6 */
	in_tid = tunnel_get6(&identity, &is_tunnel);

	if (in_tid == SIXXSD_TUNNEL_NONE)
	{
		hb_log(LOG_WARNING, src, "incoming: Unknown endpoint in \"%s\"\n", message);
		return;
	}

	tun = tunnel_grab(in_tid);
	if (!tun || tun->state == SIXXSD_TSTATE_DISABLED)
	{
		tunnel_log(SIXXSD_TUNNEL_NONE, in_tid, NULL, 0, SIXXSD_TERR_TUN_DISABLED, src);
		return;
	}

	if (tun->type != SIXXSD_TTYPE_PROTO41_HB)
	{
		tunnel_log(SIXXSD_TUNNEL_NONE, in_tid, NULL, 0, SIXXSD_TERR_HB_FOR_NON_HB, src);
		return;
	}

	/* Get the IPv4 endpoint or "sender" */
	pnt = ++pnt2;
	while (*pnt2 != '\0' && *pnt2 != ' ') pnt2++;
	if (*pnt2 == '\0')
	{
		tunnel_log(SIXXSD_TUNNEL_NONE, in_tid, NULL, 0, SIXXSD_TERR_HB_NO_IPV4, src);
		return;
	}

	*pnt2 = '\0';

	/* Does the packet specify that we should use the sender address? */
	if (strcmp(pnt, "sender") != 0)
	{
		inet_ptonA(pnt, &ip, NULL);
		if (memcmp(&ip, src, sizeof(ip)) != 0)
		{
			tunnel_log(SIXXSD_TUNNEL_NONE, in_tid, NULL, 0, SIXXSD_TERR_HB_SENDER_MISMATCH, src);
			return;
		}
	}

	strncpy(sender, pnt, sizeof(sender));
	*pnt2 = ' ';

	/* Get the date */
	pnt = ++pnt2;
	while (*pnt2 != '\0' && *pnt2 != ' ') pnt2++;
	if (*pnt2 == '\0')
	{
		tunnel_log(SIXXSD_TUNNEL_NONE, in_tid, NULL, 0, SIXXSD_TERR_HB_NOTIME, src);
		return;
	}

	*pnt2 = '\0';
	datetime = atoll((char *)pnt);
	*pnt2 = ' ';

	/* Verify the date & time */
	currtime = gettime();

	/* Calculate the difference */
	i = currtime - datetime;
	if (i < 0) i = -i;

	/* We allow the senders clock to be off */
	/* This also allows for some latency */
	if (i > MAX_CLOCK_OFF)
	{
		tunnel_log(SIXXSD_TUNNEL_NONE, in_tid, NULL, 0, SIXXSD_TERR_TUN_CLOCK_OFF, src);
		return;
	}

	/* Get the digest */
	pnt = ++pnt2;

	snprintf((char *)tmp, sizeof(tmp), "%s%s %s %" PRIu64 " %s", hb_prefix, them, sender, datetime, tun->hb_password);

	/* Generate a MD5 */
	MD5Init(&md5);
	MD5Update(&md5, tmp, strlen((char *)tmp));
	MD5Final(our_digest, &md5);

	pnt2 = (char *)tmp;
	/* make the digest */
	for (i = 0; i < 16; i++)
	{
		snprintf((char *)pnt2, 3, "%02x", *p++);
		pnt2 += 2;
	}
	*pnt2 = '\0';

	if (strcmp(pnt, (char *)tmp) != 0)
	{
		tunnel_log(SIXXSD_TUNNEL_UPLINK, in_tid, NULL, 0, SIXXSD_TERR_HB_HASHFAIL, src);
		return;
	}

	/* Goody, valid information, we love that, lets mark it up */
	tun->state = SIXXSD_TSTATE_UP;
	tun->lastbeat = currtime;
	memcpy(&tun->ip_them, src, sizeof(tun->ip_them));

	return;
}

