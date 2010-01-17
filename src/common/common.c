/*****************************************************
 SixXSd - Common Functions
******************************************************
 $Author: pim $
 $Id: common.c,v 1.10 2010-01-17 23:09:30 pim Exp $
 $Date: 2010-01-17 23:09:30 $
*****************************************************/

#include "../sixxsd.h"

/* The listen queue */
#define LISTEN_QUEUE    128

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

/* Debugging? */
/*#define DD(x) x*/
#define DD(x) {}

void dologA(int level, const char *mod, const char *fmt, va_list ap)
{
	char	buf[8192];
	bool	gotmutex = false;

#ifdef DEBUG
	/*
	 * Don't output debug information when we are not verbose enough
	 * or when debugging for that module is disabled
	 */
	if (	level == LOG_DEBUG && g_conf && (
		g_conf->verbose < 3 || (
/*
		(strcasecmp(mod, "common")	== 0 && !g_conf->verbose_common) ||
		(strcasecmp(mod, "config")	== 0 && !g_conf->verbose_config) ||
		(strcasecmp(mod, "thread")	== 0 && !g_conf->verbose_thread)
*/
		0
		)))
	{
		return;
	}
#endif

	if (level == LOG_INFO && g_conf && g_conf->verbose < 1) return;
	vsnprintf(buf, sizeof(buf), fmt, ap);

	if (g_conf)
	{
		OS_Mutex_Lock(&g_conf->mutex_log, "dolog");
		gotmutex = true;
	}

#ifndef _WIN32
	/* When daemonized and no logfile, log to syslog */
	if (g_conf && g_conf->daemonize && !g_conf->logfile) syslog(LOG_LOCAL7|level, "%s", buf);
	/* Otherwise, log to the logfile or stdout/stderr */
	else
	{
		FILE *out = (g_conf && g_conf->logfile ?
				g_conf->logfile :
				(level == LOG_DEBUG || level == LOG_ERR ? stderr : stdout));

		if (g_conf && g_conf->verbose)
		{
			fprintf(out, "[%6s : %9s] ",
				level == LOG_DEBUG ?    "debug" :
				(level == LOG_ERR ?     "error" :
				(level == LOG_WARNING ? "warn" :
				(level == LOG_NOTICE ?  "notice" :
				(level == LOG_INFO ?    "info" : "(!?)")))),
				mod);
		}
		else if (level == LOG_ERR) fprintf(out, "Error: ");
		fprintf(out, "%s", buf);
#ifdef DEBUG
		fflush(out);
#endif
	}
#else /* _WIN32 */
#ifdef _AFXDLL
	OutputDebugString(buf);
#else
	printf("%s", buf);
#ifdef DEBUG
	fflush(stdout);
#endif
#endif /* _AFXDLL */
#endif
	if (gotmutex) OS_Mutex_Release(&g_conf->mutex_log, "dolog");
}

void dolog(int level, const char *mod, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	dologA(level, mod, fmt, ap);
	va_end(ap);
}

bool openlogfile(const char *module, const char *name)
{
	if (!g_conf) return false;

	closelogfile();

	g_conf->logfile = fopen(name, "w+");
	if (g_conf->logfile)
	{
		mdolog(LOG_INFO, "Using %s as a logfile\n", name);
		return true;
	}
	else
	{
		mdolog(LOG_WARNING, "Couldn't open logfile %s\n", name);
		return false;
	}
}

void closelogfile(void)
{
	if (!g_conf) return;
	if (g_conf->logfile) fclose(g_conf->logfile);
	g_conf->logfile = NULL;
}

bool sock_init(TLSSOCKET *sock);
bool sock_init(TLSSOCKET *sock)
{
#ifdef SIXXSD_GNUTLS
	/* Allow connections to servers that have OpenPGP keys as well */
	const int       cert_type_priority[3] = { GNUTLS_CRT_X509, GNUTLS_CRT_OPENPGP, 0 };
	int             ret;
#endif /* SIXXSD_GNUTLS */

	sock->socket = -1;

#ifdef SIXXSD_GNUTLS
	/* TLS is not active yet (use sock_gotls() for that) */
	sock->tls_active = false;

	/* Initialize TLS session */
	ret = gnutls_init(&sock->session, GNUTLS_CLIENT);
	if (ret != 0)
	{
		mdolog(LOG_ERR, "TLS Init failed: %s (%d)\n", gnutls_strerror(ret), ret);
		return false;
	}

	/* Use default priorities */
	gnutls_set_default_priority(sock->session);
	/* XXX: Return value is not documented in GNUTLS documentation! */

	gnutls_certificate_type_set_priority(sock->session, cert_type_priority);
	/* XXX: Return value is not documented in GNUTLS documentation! */

	/* Configure the x509 credentials for the current session */
	gnutls_credentials_set(sock->session, GNUTLS_CRD_CERTIFICATE, g_aiccu->tls_cred);
	/* XXX: Return value is not documented in GNUTLS documentation! */

#endif /* SIXXSD_GNUTLS*/

	return true;
}

TLSSOCKET *sock_alloc(void);
TLSSOCKET *sock_alloc(void)
{
	TLSSOCKET       *sock;

	sock = (TLSSOCKET *)malloc(sizeof(*sock));
	if (!sock) return NULL;

	if (!sock_init(sock))
	{
		free(sock);
		return NULL;
	}

	return sock;
}

void sock_free(TLSSOCKET *sock);
void sock_free(TLSSOCKET *sock)
{
	if (!sock) return;

#ifdef SIXXSD_GNUTLS
	if (sock->tls_active)
	{
		sock->tls_active = false;
		gnutls_bye(sock->session, GNUTLS_SHUT_RDWR);
	}
#endif /* SIXXSD_GNUTLS*/

	if (sock->socket >= 0)
	{
		/* Stop communications */
		shutdown(sock->socket, SHUT_RDWR);
		closesocket(sock->socket);
		sock->socket = -1;
	}

#ifdef SIXXSD_GNUTLS
	gnutls_deinit(sock->session);
#endif /* SIXXSD_GNUTLS*/

	free(sock);
}

/*
 * Put a socket into TLS mode
 */
#ifdef SIXXSD_GNUTLS
bool sock_gotls(TLSSOCKET *sock)
{
	int ret = 0;

	if (!sock) return false;

	if (sock->tls_active)
	{
		mdolog(LOG_ERR, "Can't go into TLS mode twice!?\n");
		return false;
	}

	/* Set the transport */
	gnutls_transport_set_ptr(sock->session, (gnutls_transport_ptr)sock->socket);

	/* Perform the TLS handshake */
	ret = gnutls_handshake(sock->session);
	if (ret < 0)
	{
		mdolog(LOG_ERR, "TLS Handshake failed: %s (%d)\n", gnutls_strerror(ret), ret);
		return false;
	}

	mdolog(LOG_DEBUG, "TLS Handshake completed succesfully\n");

	sock->tls_active = true;

	return true;
}
#endif

/* Connect this client to a server */
TLSSOCKET *connect_client(const char *module, const char *hostname, const char *service, int family, int socktype)
{
	TLSSOCKET       *sock;
	struct addrinfo hints, *res, *ressave;

	sock = sock_alloc();
	if (!sock) return NULL;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family   = family;
	hints.ai_socktype = socktype;
	hints.ai_flags    = AI_ADDRCONFIG;

	if (getaddrinfo(hostname, service, &hints, &res) != 0)
	{
		mdolog(LOG_ERR, "Couldn't resolve host %s, service %s\n", hostname, service);
		sock_free(sock);
		return NULL;
	}

	ressave = res;

	while (res)
	{
		sock->socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sock->socket != -1)
		{
			if (connect(sock->socket, res->ai_addr, (unsigned int)res->ai_addrlen) == 0) break;

			closesocket(sock->socket);
			sock->socket = -1;
		}

		res = res->ai_next;
	}

	freeaddrinfo(ressave);

	if (sock->socket == -1)
	{
		sock_free(sock);
		sock = NULL;
	}

	return sock;
}

int listen_server(const char *module, const char *hostname, const char *service, int family, int socktype, int protocol, struct socketpool *pool, unsigned int tag)
{
	struct addrinfo	hints, *res = NULL, *ressave = NULL;
	int		n, count = 0;
	SOCKET		sock;
	int		on = 1;

	/* No socktype specified? */
	if (socktype == 0)
	{
		/* Fail if no pool was given */
		if (!pool) return 0;

		/* Recursively call itself for TCP and SCTP */
		count += listen_server(module, hostname, service, family, SOCK_STREAM, IPPROTO_TCP, pool, tag);
		count += listen_server(module, hostname, service, family, SOCK_SEQPACKET, IPPROTO_SCTP, pool, tag);
		return count;
	}

#ifndef _WIN32
	/* getaddrinfo() doesn't support AF_UNIX thus do it ourselves */
	if (family == AF_UNIX)
	{
		struct sockaddr_un	addr;
		struct stat		st;

		memset(&addr, 0, sizeof(addr));
		memset(&st, 0, sizeof(st));

		if (!hostname)
		{
			mdolog(LOG_WARNING, "listen setup: trying to listen on a unix socket but without a hostname\n");
			return pool ? 0 : -1;
		}

		sock = socket(family, socktype, protocol);
		if (sock < 0)
		{
			mdolog(LOG_WARNING, "listen setup: socket error: could not open UNIX socket\n");
			return pool ? 0 : -1;
		}

		/* The hostname is the path to the unix socket */
		strncpy(addr.sun_path, hostname, sizeof(addr.sun_path));
		addr.sun_family = AF_UNIX;
		if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
		{
			closesocket(sock);
			mdolog(LOG_WARNING, "bind setup: socket error: could not bind to UNIX socket with path %s\n", hostname);
			return pool ? 0 : -1;
		}
		listen(sock, LISTEN_QUEUE);

		mdolog(LOG_INFO, "Listening on unix://%s\n", hostname);

		socketpool_add(pool, sock, tag, AF_UNIX, IPPROTO_RAW, SOCK_STREAM);
	}
	else
	{
#endif
		memset(&hints, 0, sizeof(hints));

		/* AI_PASSIVE flag: the resulting address is used to bind
 		   to a socket for accepting incoming connections.
		   So, when the hostname==NULL, getaddrinfo function will
  		   return one entry per allowed protocol family containing
		   the unspecified address for that family. */

		hints.ai_flags    = AI_PASSIVE;
		hints.ai_family   = family;
		hints.ai_socktype = socktype;
		hints.ai_protocol = protocol;

		/* Hack: For SCTP we actually use TCP settings to ask getaddrinfo() */
		if (protocol == IPPROTO_SCTP)
		{
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = IPPROTO_TCP;
		}

		n = getaddrinfo(hostname, service, &hints, &res);
		ressave=res;
		if (n < 0)
		{
			mdolog(LOG_WARNING, "listen_server(%s:%s %u %u %u) setup: getaddrinfo error: %s\n",
				hostname, service, family, protocol, socktype, gai_strerror(n));
			if (ressave) freeaddrinfo(ressave);
			return pool ? 0 : -1;
		}

		/* Try to open socket with each address getaddrinfo returned,
 		   until we get one valid listening socket. */
		sock = -1;
		while (res)
		{
			/* Hack: Fixup the SCTP socktype+protocol */
			if (protocol == IPPROTO_SCTP)
			{
				res->ai_socktype = SOCK_SEQPACKET;
				res->ai_protocol = IPPROTO_SCTP;
			}

			sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			if (!(sock < 0))
			{
				on = 1;
				setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
				on = 1;
				setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char *)&on, sizeof(on));
				on = 1;
				setsockopt(sock, SOL_IPV6, IPV6_V6ONLY, &on, sizeof(on));

				if (bind(sock, res->ai_addr, (int)res->ai_addrlen) == 0)
				{
					/* Listen on the socket */
					listen(sock, LISTEN_QUEUE);

					mdolog(LOG_INFO, "Listening on %s://%s%s%s:%s (%s:%u)\n",
						res->ai_protocol == IPPROTO_UDP ? "udp" :
						(res->ai_protocol == IPPROTO_TCP ? "tcp" :
						(res->ai_protocol == IPPROTO_SCTP ? "sctp" : "??")),
						res->ai_family == AF_INET6 ? "[" : "",
						hostname ? hostname : (res->ai_family == AF_INET6 ? "::" : "."),
						res->ai_family == AF_INET6 ? "]" : "",
						service,
						(res->ai_socktype == SOCK_STREAM ? "stream" :
						(res->ai_socktype == SOCK_DGRAM ? "datagram" :
						(res->ai_socktype == SOCK_SEQPACKET ? "seqpacket" : "unknown"))),
						res->ai_socktype);

					if (!pool)
					{
						if (ressave) freeaddrinfo(ressave);
						return sock;
					}

					socketpool_add(pool, sock, tag, res->ai_family, res->ai_protocol, res->ai_socktype);
					count++;

					/* Try to listen on more sockets */
				}
				else
				{
					closesocket(sock);
					sock = -1;
				}
			}
			res = res->ai_next;
		}

		freeaddrinfo(ressave);
#ifndef _WIN32
	}
#endif

	if (count == 0)
	{
		mdolog(LOG_WARNING, "listen setup: socket error: could not open a socket of %s:%s over %s (%u) using protocol: %s (%u) sockettype: %s (%u)\n",
			hostname, service,
			family == AF_INET ? "IPv4" :
			(family == AF_INET6 ? "IPv6" :
			(family == AF_UNSPEC ? "unspecified" : "??")),
			family,
			protocol == IPPROTO_UDP ? "UDP" : (protocol == IPPROTO_TCP ? "TCP" : (protocol == IPPROTO_SCTP ? "SCTP" : "??")),
			protocol,
			socktype == SOCK_DGRAM ? "datagram" : (socktype == SOCK_STREAM ? "stream" :  (socktype == SOCK_SEQPACKET ? "seqpacket" : "??")),
			socktype);
	}

	return pool ? count : (count == 0 ? -1 : count);
}

bool uri_parse_host(const char *module, const char *uri, char *host, unsigned int len);
bool uri_parse_host(const char *module, const char *uri, char *host, unsigned int len)
{
	const char	*u = uri, *s;
	unsigned int	i;

	/* Literal IPv6 address notation? (RFC2732) */
	if (*u == '[')
	{
		/* skip the '[' marker and find the next, closing, one ']' */
		u++;
		s = strchr(u, ']');
		if (!s)
		{
			mdolog(LOG_ERR, "Literal IPv6 address was not terminated in %s\n", uri);
			return false;
		}
		/* copy the string ;) */
		i = s-u;
		strncpy(host, u, (i > len ? len : i));
	}
	else
	{
		/* Check for a portnumber */
		s = strchr(u, ':');
		if (!s)
		{
			s = strchr(u, '/');
			i = s-u;
			/* - No port nor any options, just copy it all */
			/* - No port but there are options -> copy upto options */
			strncpy(host, u, !s ? len : (i > len ? len : i));
		}
		else
		{
			i = s-u;
			strncpy(host, u, (i > len ? len : i));
		}
	}
	return true;
}

bool uri_parse_service(const char *uri, char *service, unsigned int len);
bool uri_parse_service(const char *uri, char *service, unsigned int len)
{
	const char	*u = uri;
	char 		*s;
	unsigned int 	i;

	/* Check for a port number */
	s = strchr(u, ':');
	if (s)
	{
		u = s+1;
		/* Find the end */
		s = strchr(u, '/');
		i = s-u;
		strncpy(service, u, !s ? len : (i > len ? len : i));
	}
	return true;
}

/* Parse an URI and return a socketpool
 * Supported URI format:
 *	((tcp|udp|sctp)[4|6])|unix)://(host[:service]|unixpath)
 *
 * The only options supported by this routine is 'bind' to allow binding to a local host when connecting outbound.
 *
 * eg:
 *  tcp://localhost:chariot
 *  udp6://[::1]:12345
 *  unix:///tmp/chariot.socket
 *
 *  udp://192.0.2.111:2055/bind=192.0.2.1:2345
 *   This will bind to 192.0.2.1 port 2345 (host/servicenames allowed too of course)
 *   and then connect outbound to 192.0.2.111 port 2055.
 *   This allows opening of firewalls to permit exactly that traffic or one could
 *   put the collector behind a NAT/firewall, let the collector sometimes send packets
 *   from 192.0.2.111:2055 to 192.0.2.111:2055, this will cause the NAT/firewall to
 *   establish a flow for that connection allowing  to send packets into the
 *   network, basically easily circumventing network policies.
 *
 * unix:// is not supported on Win32 as it doesn't exist on that platform
 */
int use_uriA(const char *module, const char *uri, const char *defaultservice, struct socketpool *pool, unsigned int tag);
int use_uriA(const char *module, const char *uri, const char *defaultservice, struct socketpool *pool, unsigned int tag)
{
	char		host[NI_MAXHOST], service[NI_MAXSERV], *hostname = host,
			bind_host[NI_MAXHOST], bind_service[NI_MAXSERV];
	const char	*u = uri, *s;
	int		family = AF_UNSPEC, socktype = 0, protocol = 0;
	size_t		i;

	/* Empty the host & service */
	memset(host, 0, sizeof(host));
	memset(service, 0, sizeof(service));
	memset(bind_host, 0, sizeof(bind_host));
	memset(bind_service, 0, sizeof(bind_service));

	/* Default to the defaultservice */
	if (defaultservice) strncpy(service, defaultservice, sizeof(service));

	/* Determine the socktype + protocol */
	if (strncmp(uri, "tcp://", 6) == 0)
	{
		socktype = SOCK_STREAM;
		u+=6;
	}
	else if (strncmp(uri, "tcp4://", 7) == 0)
	{
		family = AF_INET;
		socktype = SOCK_STREAM;
		u+=7;
	}
	else if (strncmp(uri, "tcp6://", 7) == 0)
	{
		family = AF_INET6;
		socktype = SOCK_STREAM;
		u+=7;
	}
	else if (strncmp(uri, "udp://", 6) == 0)
	{
		socktype = SOCK_DGRAM;
		u+=6;
	}
	else if (strncmp(uri, "udp4://", 7) == 0)
	{
		family = AF_INET;
		socktype = SOCK_DGRAM;
		u+=7;
	}
	else if (strncmp(uri, "udp6://", 7) == 0)
	{
		family = AF_INET6;
		socktype = SOCK_DGRAM;
		u+=7;
	}
	else if (strncmp(uri, "sctp://", 7) == 0)
	{
		socktype = SOCK_SEQPACKET;
		protocol = IPPROTO_SCTP;
		u+=7;
	}
	else if (strncmp(uri, "sctp4://", 8) == 0)
	{
		family = AF_INET;
		socktype = SOCK_SEQPACKET;
		protocol = IPPROTO_SCTP;
		u+=8;
	}
	else if (strncmp(uri, "sctp6://", 8) == 0)
	{
		family = AF_INET6;
		socktype = SOCK_SEQPACKET;
		protocol = IPPROTO_SCTP;
		u+=8;
	}
#ifndef _WIN32
	else if (strncmp(uri, "unix://", 7) == 0)
	{
		family = AF_UNIX;
		socktype = SOCK_DGRAM;
		protocol = 0;
		u+=7;
	}
#endif
	else if (strncmp(uri, "all://", 6) == 0 ||
		 strncmp(uri, "any://", 6) == 0)
	{
		u+=6;
	}
	else if (strncmp(uri, "all4://", 7) == 0 ||
		 strncmp(uri, "any4://", 7) == 0)
	{
		family = AF_INET;
		u+=7;
	}
	else if (strncmp(uri, "all6://", 7) == 0 ||
		 strncmp(uri, "any6://", 7) == 0)
	{
		family = AF_INET6;
		u+=7;
	}
	else
	{
		mdolog(LOG_ERR, "URI %s doesn't contain a valid protocol\n", uri);
		return -1;
	}

	/* Skip the format, if there is one */
	s = strchr(u, '@');
	if (s) u = s+1;

#ifndef _WIN32
	/* For AF_UNIX the rest is the path to the socket */
	if (family == AF_UNIX)
	{
		i = strlen(u);
		strncpy(host, u, (i > sizeof(host) ? sizeof(host) : i));
	}
	/* Handle TCP/UDP/SCTP which have a host[:port] notation */
	else
	{
#endif
		uri_parse_host(module, u, host, sizeof(host));

		/* Did we find the mandatory host? */
		if (strlen(host) == 0)
		{
			mdolog(LOG_ERR, "No host specified in uri %s\n", uri);
			return -1;
		}

		/* Skip past the host */
		u+=strlen(host);

		/* any host? (eg all://any:2055) */
		if (strcasecmp("any", host) == 0) hostname = NULL;

		/* Parse the service */
		uri_parse_service(u, service, sizeof(service));

		/* Check if there is a bind option after this */
		s = strstr(u, "bind=");
		if (s)
		{
			/* Skip the 'bind=' */
			u = s + 5;

			/* Parse the service */
			uri_parse_host(module, u, bind_host, sizeof(bind_host));

			/* Skip past the bind_host */
			u+=strlen(bind_host);

			/* Parse the service */
			uri_parse_service(u, bind_service, sizeof(bind_service));
		}
#ifndef _WIN32
	}
#endif

	/* Try to connect to the client or listen as a server using these values */
	return listen_server(module, hostname, service[0] == '\0' ? NULL : service, family, socktype, protocol, pool, tag);
}

/* Split the URI up into multiple segments (separated by a space) and feed it to use_uriA */
int use_uri(const char *module, const char *uri, const char *defaultservice, struct socketpool *pool, unsigned int tag)
{
	int	fields = countfields(uri), i = 0;
	char	val[256];
	int	ret = 0;

        for (i=1; i <= fields; i++)
        {
                if (!copyfield(uri, i, val, sizeof(val)) || strlen(val) == 0) continue;
		ret += use_uriA(module, val, defaultservice, pool, tag);
	}
	return ret;
}

void sock_printf(TLSSOCKET *sock, const char *fmt, ...)
{
	char		buf[2048];
	unsigned int	len = 0, done = 0;
	int		ret;

	va_list ap;
	va_start(ap, fmt);

	/* When not a socket send it to the logs */
	if (sock == NULL || sock->socket == -1) dologA(LOG_INFO, "common", fmt, ap);
	else
	{
		/* Format the string */
		len = vsnprintf(buf, sizeof(buf), fmt, ap);

		/* Send the line(s) over the network */
		while (done < len)
		{
#ifdef SIXXSD_GNUTLS
			if (sock->tls_active) ret = gnutls_record_send(sock->session, &buf[done], len-done);
			else
#endif
			ret = send(sock->socket, buf, len, MSG_NOSIGNAL);

			if (ret > 0) done += ret;
			else break;
		}

#if 0
		/* Show this as debug output */
		if (g_conf->verbose)
		{
			/* Strip the last \n */
			len = (int)strlen(buf);
			if (len > 0) buf[len-1] = '\0';
			/* dump the information */
			ddolog("common", "sock_printf()  : \"%s\"\n", buf);
		}
#endif
	}
	va_end(ap);
}

/* Parse a URI and return the username and password */
bool parse_userpass(const char *uri, char *username, unsigned int username_len, char *password, unsigned int password_len)
{
	/* 's' = start of the username
	 * 'm' = end of the username and/or begin of password
	 * 'u' = end of password or username
	 * 'e' = tmp
	 */
	const char *s = uri, *u = NULL, *m = NULL;
	unsigned int e;

	/* Clear the return values */
	if (username) memset(username, 0, username_len);
	if (password) memset(password, 0, password_len);

	/* Skip the protocol declaration */
	s = strstr(uri, "://");
	/* If it doesn't have a protocol, fail */
	if (!s) return false;
	s+=3;

	/* Try to find a colon */
	m = strchr(s, ':');

	/* Now find the '@' sign which delimits to the host */
	u = strchr(s, '@');
	/* If it doesn't include a host, fail */
	if (!u) return false;

	/* if the ':' is after the '@' it is a port and there is no password */
	if (m && m > u) m = NULL;

	/* Copy the username */
	if (m) e = (unsigned int)(m-s);
	else e = (unsigned int)(u-s);
	if (username) memcpy(username, s, username_len < e ? username_len : e);

	/* Copy the password if any */
	if (m)
	{
		e = (unsigned int)(u-m-1);
		if (password) memcpy(password, m+1, password_len < e ? password_len : e);
	}

	return true;
}

/*
 * Read a line from a socket and store it in ubuf
 * Note: uses internal caching, this should be the only function
 * used to read from the sock! The internal cache is rbuf.
 */
int sock_getline(TLSSOCKET *sock, char *rbuf, unsigned int rbuflen, unsigned int *filled, char *ubuf, unsigned int ubuflen)
{
	unsigned int j;
	int i;

	if (!sock) return -1;

	/* A closed socket? -> clear the buffer */
	if (sock->socket == -1)
	{
		memset(rbuf, 0, rbuflen);
		*filled = 0;
		return -1;
	}

	/* Clear the caller supplied buffer, just in case */
	memset(ubuf, 0, ubuflen);

	for (;;)
	{
		DD(ddolog("common", "gl() - Filled %u\n", *filled);)

		/* Did we still have something in the buffer? */
		if (*filled > 0)
		{
			DD(ddolog("common", "gl() - Seeking newline (filled %u)\n", *filled);)

			/* Walk to the end or until we reach a \n */
			for (j=0; (j < (*filled-1)) && (rbuf[j] != '\n'); j++);

			DD(ddolog("common", "gl() - Seeking newline - end\n");)

			/* Did we find a newline? */
			if (rbuf[j] == '\n')
			{
				DD(ddolog("common", "gl() - Found newline at %u\n", j);)

				/* Newline with a Linefeed in front of it ? -> remove it */
				if (rbuf[j] == '\n' && rbuf[j-1] == '\r')
				{
					DD(ddolog("common", "gl() - Removing LF\n");)
					j--;
				}
				DD(else ddolog("common", "gl() - No LF\n");)

				/* Copy this over to the caller */
				memcpy(ubuf, rbuf, j);

				DD(ddolog("common", "gl() - Copied\n");)

				/* Count the \r if it is there */
				if (rbuf[j] == '\r') j++;
				/* Count the \n */
				j++;

				/* filled = what is left in the buffer */
				*filled -= j;

				/* Now move the rest of the buffer to the front */
				if (*filled > 0) memmove(rbuf, &rbuf[j], *filled);
				else *filled = 0;

				DD(ddolog("common", "getline() - \"%s\", len = %u\n", ubuf, j);)

				/* We got ourselves a line in 'buf' thus return to the caller */
				return j;
			}
		}

		DD(ddolog("common", "gl() - Trying to receive...\n");)

		/* Fill the rest of the buffer */
#ifdef SIXXSD_GNUTLS
		if (sock->tls_active) i = gnutls_record_recv(sock->session, &rbuf[*filled], rbuflen-*filled-10);
		else
#endif
		i = recv(sock->socket, &rbuf[*filled], rbuflen-*filled-128, 0);

		DD(ddolog("common", "gl() - Received %d, errno: %s (%d)\n", i, strerror(errno), errno);)

		/* Orderly shutdown */
		if (i == 0) return -1;

		/* Fail on errors */
		if (i < 0)
		{
			if (errno == EAGAIN)
			{
				DD(ddolog("common", "gl() - Try Again / Would block\n");)
				return 0;
			}

			/* Fail */
			return -1;
		}

		/* We got more filled space! */
		*filled+=i;

		/* Buffer overflow? */
		if (*filled >= (rbuflen-64))
		{
			dolog(LOG_ERR, "common", "Buffer almost flowed over without receiving a newline (filled=%u, rbuflen=%u)\n", *filled, rbuflen);
			return -1;
		}

		/* And try again in this loop ;) */
	}

	/* Never reached */
	return -1;
}

/* Count the number of fields in <s> */
unsigned int countfields(const char *s)
{
	int	n = 1, i;

	if (s == NULL || strlen(s) == 0) return 0;
	for (i=0; s[i] != '\0'; i++) if (s[i] == ' ') n++;
	return n;
}

/*
 * Copy <count> fields starting with <n> of string <s> into <buf> with a maximum of buflen
 * First field is 1
 */
bool copyfields(const char *s, unsigned int field, unsigned int count, char *buf, unsigned int buflen)
{
	unsigned int	begin = 0, i = 0, f = field, c = count;
	bool		deltrail = false;

	/* Clear the buffer */
	memset(buf, 0, buflen);

	/* Remove leading and trailing quote if they are there */
	begin = strlen(s);
	if (begin > 0 && s[0] == '"') i=1;
	if (begin > 0 && s[begin-1] == '"') deltrail = true;

	/* Copy at least 1 field */
	if (c > 0) c--;

	begin = 0;
	while (s[i] != '\0')
	{
		/*
		 * When the beginning is not found yet update it
		 * and proceed to the next field
		 */
		if (f > 0)
		{
			f--;
			begin = i;
		}
		/* We found another field */
		else if (c > 0) c--;

		for (;s[i] != '\0' && s[i] != ' '; i++);

		/* Found our field? */
		if (f == 0 && (c == 0 || count == 0))
		{
			/* When only n fields where requested */
			if (count != 0) i-=begin;
			/* User wanted everything */
			else i=(unsigned int)strlen(s)-begin;

			/* Trailing quote? */
			if (deltrail && ((begin+i) >= strlen(s))) i--;

			/* Copy it to the supplied buffer as long as it fits */
			strncpy(buf, s+begin, i > buflen ? buflen : i);

			DD(ddolog("common", "copyfield() : '%s', begin = %u, len = %u (\"%s\", f=%u, count=%u, c=%u)\n", buf, begin, i, s, field, count, c);)
			return true;
		}
		
		i++;
	}
	dolog(LOG_WARNING, "common", "copyfield() - Field %u+%u didn't exist in '%s'\n", field, count, s);
	return false;
}


/* Not the most efficient but works */
bool findfield(const char *s, const char *f)
{
	unsigned int fields = countfields(s), i;
	char buf[100];

	for (i=0;i<fields;i++)
	{
		if (!copyfields(s, i, 1, buf, sizeof(buf))) return false;
		if (strcasecmp(f,s) == 0) return true;
	}
	return false;
}

#ifdef _WIN32
/* There is no inet_ntop() on Windows, thus we code it ourselves */
const char *inet_ntop(int af, const void *src, char *dst, socklen_t cnt)
{
	socklen_t		sockaddrlen;
	int			retval = -1;
	struct sockaddr		*sa = NULL;
	struct sockaddr_in	sa4;
	struct sockaddr_in6	sa6;

	if (!dst) return NULL;

	memset(dst, 0, cnt);
	memset(&sa4, 0, sizeof(sa4));
	memset(&sa6, 0, sizeof(sa6));

	if (af == AF_INET)
	{
		sockaddrlen = sizeof(struct sockaddr_in);
		sa = (struct sockaddr *)&sa4;
		sa4.sin_family = af;
		memcpy(&sa4.sin_addr, src, sizeof(struct in_addr));
	}
	else if (af == AF_INET6)
	{
		sockaddrlen = sizeof(struct sockaddr_in6);
		sa = (struct sockaddr *)&sa6;
		sa6.sin6_family = af;
		memcpy(&sa6.sin6_addr, src, sizeof(struct in6_addr));
	}
	/* AF not supported */
	else
	{
		dolog(LOG_ERR, "common", "inet_ntop() - Unsupported AF %u passed\n", af);
		return NULL;
	}

	return getnameinfo(sa, sockaddrlen, dst, cnt, NULL, 0, NI_NUMERICHOST) != 0 ? NULL : dst;
}
#endif /* _WIN32 */

/*
 * Get Socket Name for local or peer
 * Fixes up IPv4 mapped ::ffff:x.x.x.x and compatible (::x.x.x.x) IPv6 addresses so that
 * we handle them correctly as IPv4 and not IPv6, which they are not.
 * Returns the family of the thing.
 */
void socket_cleanss(struct sockaddr_storage *ss)
{
	if (ss->ss_family == AF_INET6 &&
		(IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)ss)->sin6_addr) ||
		 IN6_IS_ADDR_V4COMPAT(&((struct sockaddr_in6 *)ss)->sin6_addr)))
	{
		/* Move the IPv4 address into the correct place */
		memmove(	&((struct sockaddr_in *)ss)->sin_addr,
				(char *)(&((struct sockaddr_in6 *)ss)->sin6_addr)+12, 4);

		/* It's IPv4 now */
		ss->ss_family = AF_INET;
	}
}

#define LISTEN_QUEUE    128

void socketpool_init(struct socketpool *pool)
{
	FD_ZERO(&pool->fds);
	pool->hi = 0;
	List_New(&pool->sockets);
}

void socketpool_exit(struct socketpool *pool)
{
	struct socketnode *sn, *sn2;

	if (!pool) return;

	/* Remove all the sockets in the pool */
	List_For(&pool->sockets, sn, sn2, struct socketnode *)
	{
		socketpool_remove(pool, sn);
		free(sn);
	}
}

struct socketnode *socketpool_accept(struct socketpool *pool, struct socketnode *sn_a, unsigned int tag)
{
	struct sockaddr_storage	sa;
	socklen_t		addrlen = sizeof(sa);
	struct socketnode	*sn;

	SOCKET sock = accept(sn_a->socket.socket, (struct sockaddr *)&sa, &addrlen);

	/* Directly return on failures */
	if (sock == -1)
	{
		dolog(LOG_ERR, "common", "Couldn't accept a new client with tag %u\n", tag);
		return NULL;
	}

	/* Add the client to the pool */
	sn = socketpool_add(pool, sock, tag, sn_a->family, sn_a->protocol, sn_a->socktype);

	/* XXX record some information into the socketnode (remote host etc) */
	ddolog("common", "Accepted %u with tag %u\n", sn->socket.socket, tag);
	sn->lastrecv = time(NULL);
	return sn;
}

struct socketnode *socketpool_add(struct socketpool *pool, SOCKET sock, unsigned int tag, uint16_t family, uint16_t protocol, uint16_t socktype)
{
	struct socketnode	*sn;

	/* Allocate space for a new socketnode */
	sn = malloc(sizeof(*sn));
	if (!sn)
	{
		dolog(LOG_INFO, "common", "Couldn't allocate memory for socketndoe: %s\n", strerror(errno));
		return NULL;
	}
	/* Clear it out */
	memset(sn, 0, sizeof(*sn));

	if (!sock_init(&sn->socket))
	{
		free(sn);
		return NULL;
	}

	/* Socketnode */
	sn->socket.socket = sock;
	sn->tag		= tag;
	sn->family	= family;
	sn->protocol	= protocol;
	sn->socktype	= socktype;

	/* Add the socket to the pool */
	List_AddTail(&pool->sockets, sn);

	/* Make select() aware of the socket */
	FD_SET(sock, &pool->fds);
	if (sock > pool->hi) pool->hi = sock;

	return sn;
}

void socketpool_remove(struct socketpool *pool, struct socketnode *sn)
{
	if (sn->socket.socket != -1)
	{
		shutdown(sn->socket.socket, SHUT_RDWR);
		closesocket(sn->socket.socket);
		FD_CLR(sn->socket.socket, &pool->fds);
	}

	/* Remove it from the socket list */
	List_Remove(sn);
}

/*
 * Read a line from a socket and store it in ubuf
 * Note: uses internal caching, this should be the only function
 * used to read from the sock! The internal cache is rbuf.
 */
int sock_getdata(SOCKET sock, char *rbuf, unsigned int rbuflen, unsigned int *filled);
int sock_getdata(SOCKET sock, char *rbuf, unsigned int rbuflen, unsigned int *filled)
{
	int i;

	/* A closed socket? -> clear the buffer */
	if (sock == -1)
	{
		memset(rbuf, 0, rbuflen);
		*filled = 0;
		return -1;
	}

	/* Fill the rest of the buffer */
	i = recv(sock, &rbuf[*filled], rbuflen-*filled-10, 0);

	/* Fail on errors */
	if (i <= 0) return -1;

	/* We got more filled space! */
	*filled+=i;

	/* Buffer overflow? */
	if (*filled >= (rbuflen-10))
	{
		dolog(LOG_ERR, "common", "Buffer almost flowed over\n");
		return -1;
	}

	return *filled;
}

int sock_done(SOCKET UNUSED sock, char *rbuf, unsigned int UNUSED rbuflen, unsigned int *filled, unsigned int amount);
int sock_done(SOCKET UNUSED sock, char *rbuf, unsigned int UNUSED rbuflen, unsigned int *filled, unsigned int amount)
{
	/* Done with this part */
	*filled-=amount;

	/* Move the leftovers to the front */
	memmove(rbuf, &rbuf[amount], *filled);
	
	return *filled;
}

int sn_dataleft(struct socketnode *sn)
{
	return sn->filled;
}

int sn_getdata(struct socketnode *sn)
{
	return sock_getdata(sn->socket.socket, sn->buf, sizeof(sn->buf), &sn->filled);
}

int sn_done(struct socketnode *sn, unsigned int amount)
{
	return sock_done(sn->socket.socket, sn->buf, sizeof(sn->buf), &sn->filled, amount);
}

int sn_getline(struct socketnode *sn, char *ubuf, unsigned int ubuflen)
{
	return sock_getline(&sn->socket, sn->buf, sizeof(sn->buf), &sn->filled, ubuf, ubuflen);
}

void socket_setnonblockA(SOCKET sock)
{
	int flags;

#ifdef O_NONBLOCK
	if (-1 == (flags = fcntl(sock, F_GETFL, 0))) flags = 0;
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#else
	/* Otherwise, use the old way of doing it */
	flags = 1;
	ioctl(sock, FIOBIO, &flags);
#endif
}

void socket_setblockA(SOCKET sock)
{
	int flags;

#ifdef O_NONBLOCK
	if (-1 == (flags = fcntl(sock, F_GETFL, 0))) flags = 0;
	fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
#else
	/* Otherwise, use the old way of doing it */
	flags = 0;
	ioctl(sock, FIOBIO, &flags);
#endif
}

void socket_setnonblock(TLSSOCKET *sock)
{
	socket_setnonblockA(sock->socket);
}

void socket_setblock(TLSSOCKET *sock)
{
	socket_setblockA(sock->socket);
}
