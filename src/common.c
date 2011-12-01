/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2011 All Rights Reserved
************************************************************
 $Author: $
 $Id: $
 $Date: $
***********************************************************/

#include "sixxsd.h"

/* Debugging? */
#ifdef DEBUGALL
#define DD(x) x
#else
#define DD(x) {}
#endif

const uint8_t ipv4_mapped_ipv6_prefix[12] = {0,0,0,0,0, 0,0,0,0,0, 0xff, 0xff };

PTR *mrealloc(PTR *ptr, size_t newsize, size_t oldsize)
{
	ptr = realloc(ptr, newsize);
	if (ptr && newsize > oldsize) memzero(&(((char *)ptr)[oldsize]), newsize - oldsize);
	return ptr;
}

VOID doelog(int level, int errnum, const char *module, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	doelogA(level, errnum, module, fmt, ap);
	va_end(ap);
}

VOID dolog(int level, const char *module, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	doelogA(level, 0, module, fmt, ap);
	va_end(ap);
}

VOID sock_setnonblock(SOCKET sock)
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

VOID sock_setblock(SOCKET sock)
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

static int snprintef(char *str, size_t size, int errnum, const char *ATTR_RESTRICT format, ...) ATTR_FORMAT(printf, 4, 5);
static int snprintef(char *str, size_t size, int errnum, const char *format, ...)
{
	va_list		ap;
	unsigned int	i;
	int		k;

	/* Print the message */
	va_start(ap, format);
	k = vsnprintf(str, size, format, ap);
	va_end(ap);

	/* Append errno description? */
	if (errnum != 0)
	{
		i = strlen(str);
		if (i == 0) i = 1;
		if (i < (size-10))
		{
			/* Add ": " overwriting the \n which has to be present */
			str[i-1] = ':';
			str[i] = ' ';
			str[i+1] = '\0';

			errno = 0;
			strerror_r(errnum, &str[i+1], size - (i+2));

			i = strlen(str);
			k = snprintf(&str[i], size-i, " (errno %d)\n", errnum);
			if (!snprintfok(k, size-i))
			{
				/* Doesn't hurt when it doesn't fit, just terminate it */
				str[i] = '\0';
			}
		}
	}

	return k;
}

static SOCKET sock_connect_unix(char *buf, unsigned int buflen, const char *hostname, int family, int socktype, int protocol);
static SOCKET sock_connect_unix(char *buf, unsigned int buflen, const char *hostname, int family, int socktype, int protocol)
{
	SOCKET			sock;
	struct sockaddr_un	addr;

	memzero(&addr, sizeof(addr));

	if (!hostname)
	{
		snprintf(buf, buflen, "Listen setup: trying to listen on a unix socket but without a hostname\n");
		return INVALID_SOCKET;
	}

	sock = socket(family, socktype, protocol);
	if (sock == INVALID_SOCKET)
	{
		snprintef(buf, buflen, errno, "Listen setup: socket error: could not open UNIX socket\n");
		return INVALID_SOCKET;
	}

	/* The hostname is the path to the unix socket */
	strncpy(addr.sun_path, hostname, sizeof(addr.sun_path) - 1);
	addr.sun_family = AF_UNIX;
	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
	{
		snprintef(buf, buflen, errno, "Connect: socket error: could not connect to UNIX socket with path %s\n", hostname);
		closesocket(sock);
		return INVALID_SOCKET;
	}

	return sock;
}

SOCKET sock_connect(char *buf, unsigned int buflen, const char *hostname, const char *service, int family, int socktype, int protocol, const char *bind_hostname, const char *bind_service)
{
	struct addrinfo	hints, *res, *ressave, hints2, *res2, *ressave2;
	int		n;
	SOCKET		sock;
	socklen_t	on = 1;

	/* getaddrinfo() doesn't support AF_UNIX thus do it ourselves */
	if (family == AF_UNIX) return sock_connect_unix(buf, buflen, hostname, family, socktype, protocol);

	memzero(&hints, sizeof(hints));

	hints.ai_family = family;
	hints.ai_socktype = socktype;
	hints.ai_protocol = protocol;
	hints.ai_flags = AI_ADDRCONFIG;

	n = getaddrinfo(hostname, service, &hints, &res);

	if (n < 0)
	{
		snprintf(buf, buflen, "connect_client(\"%s\":\"%s\") - getaddrinfo error: [%s]\n", hostname, service, gai_strerror(n));
		return INVALID_SOCKET;
	}

	ressave = res;

	sock = INVALID_SOCKET;

	while (res)
	{
		sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sock != INVALID_SOCKET)
		{
			if (bind_hostname || bind_service)
			{
				/* Allow re-use of an address (saving problems when a connection still exists on that socket */
				on = 1;
				setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
				on = 1;
				setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char *)&on, sizeof(on));
				on = 1;
				setsockopt(sock, SOL_IPV6, IPV6_V6ONLY, &on, sizeof(on));

				/* Clean the hints */
				memzero(&hints2, sizeof(hints2));

				/* AI_PASSIVE flag: the resulting address is used to bind
 				 * to a socket for accepting incoming connections.
				 * So, when the hostname==NULL, getaddrinfo function will
  				 * return one entry per allowed protocol family containing
				 * the unspecified address for that family.
				 */
				hints2.ai_flags    = AI_PASSIVE;
				hints2.ai_family   = family;
				hints2.ai_socktype = socktype;
				hints2.ai_protocol = protocol;

				n = getaddrinfo(bind_hostname, bind_service, &hints, &res2);
				if (n < 0)
				{
					snprintf(buf, buflen, "connect_client(%s:%s) - bind getaddrinfo error: %s\n",
						bind_hostname ? bind_hostname : "<any>",
						bind_service ? bind_service : "<any>",
						gai_strerror(n));
					closesocket(sock);
					sock = INVALID_SOCKET;
					break;
				}
				ressave2=res2;

				while (res2)
				{
					if (bind(sock, res2->ai_addr, (int)res2->ai_addrlen) == 0) break;
					res = res->ai_next;
				}

				if (!res2)
				{
					snprintef(buf, buflen, errno, "connect_client() - Could not bind to %s%s%s%s\n",
						bind_hostname ? "host " : "",
						bind_hostname ? bind_hostname : NULL,
						bind_service ? "service " : "",
						bind_service ? bind_service : NULL);

					closesocket(sock);
					sock = INVALID_SOCKET;
					break;
				}

				freeaddrinfo(ressave2);
			}

			if (connect(sock, res->ai_addr, (int)res->ai_addrlen) == 0)
			{
				break;
			}
			else
			{
				snprintef(buf, buflen, errno, "connect_client() - failed to connect\n");
				closesocket(sock);
				sock = INVALID_SOCKET;
			}
		}
		else
		{
			snprintef(buf, buflen, errno, "connect_client() - couldn't get a socket of family %s (%u), type %s (%u), proto %u\n",
				(res->ai_family == AF_INET ? "IPv4" :
				(res->ai_family == AF_INET6 ? "IPv6" : "unknown")),
				res->ai_family,

				(res->ai_socktype == SOCK_STREAM ? "stream" :
				(res->ai_socktype == SOCK_DGRAM ? "datagram" :
				(res->ai_socktype == SOCK_SEQPACKET ? "seqpacket" : "unknown"))),
				res->ai_socktype,

				res->ai_protocol);
		}
		res = res->ai_next;
	}

	freeaddrinfo(ressave);
	return sock;
}

static int sock_listen(char *buf, unsigned int buflen, const char *hostname, const char *service, int family, int socktype, int protocol, struct socketpool *pool, uint32_t tag);
static int sock_listen(char *buf, unsigned int buflen, const char *hostname, const char *service, int family, int socktype, int protocol, struct socketpool *pool, uint32_t tag)
{
	struct addrinfo	hints, *res = NULL, *ressave = NULL;
	int		n, count = 0;
	SOCKET		sock;
	int		on = 1;

	/* Fail if no pool was given */
	if (!pool) return 0;

	/* No socktype specified? */
	if (socktype == 0)
	{
		/* Recursively call itself for TCP, UDP and SCTP */
		count += sock_listen(buf, buflen, hostname, service, family, SOCK_STREAM, IPPROTO_TCP, pool, tag);
		count += sock_listen(buf, buflen, hostname, service, family, SOCK_DGRAM, IPPROTO_UDP, pool, tag);
/*		count += sock_listen(buf, buflen, hostname, service, family, SOCK_SEQPACKET, IPPROTO_SCTP, pool, tag); */
		return count;
	}

	/* getaddrinfo() doesn't support AF_UNIX thus do it ourselves */
	if (family == AF_UNIX)
	{
		struct sockaddr_un	addr;
		struct stat		st;

		memzero(&addr, sizeof(addr));
		memzero(&st, sizeof(st));

		if (!hostname)
		{
			snprintf(buf, buflen, "listen setup: trying to listen on a unix socket but without a hostname\n");
			return 0;
		}

		sock = socket(family, socktype, protocol);
		if (sock == INVALID_SOCKET)
		{
			snprintf(buf, buflen, "listen setup: socket error: could not open UNIX socket\n");
			return 0;
		}

		/* Remove the old socket, but check first if it was a socket */
		if (stat(hostname, &st) == 0 && S_ISSOCK(st.st_mode))
		{
			snprintf(buf, buflen, "Removing old UNIX socket: %s\n", hostname);
			if (unlink(hostname) != 0 && errno != ENOENT) snprintef(buf, buflen, errno, "Couldn't remove old socket file %s\n", hostname);
		}

		/* The hostname is the path to the unix socket */
		strncpy(addr.sun_path, hostname, sizeof(addr.sun_path) - 1);
		addr.sun_family = AF_UNIX;
		if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
		{
			snprintef(buf, buflen, errno, "bind setup: socket error: could not bind to UNIX socket with path %s\n", hostname);
			closesocket(sock);
			return 0;
		}

		listen(sock, LISTEN_QUEUE);

		snprintf(buf, buflen, "Listening on unix://%s\n", hostname);

		socketpool_add(pool, sock, tag, AF_UNIX, IPPROTO_RAW, SOCK_STREAM);
	}
	else
	{
		memzero(&hints, sizeof(hints));

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
		if (n < 0)
		{
			snprintf(buf, buflen, "listen_server(%s:%s %u %u %u) setup: getaddrinfo error: %s\n",
				hostname, service, family, protocol, socktype, gai_strerror(n));
			return 0;
		}

		ressave=res;

		/* Try to open socket with each address getaddrinfo returned,
 		   until we get one valid listening socket. */
		sock = INVALID_SOCKET;

		while (res)
		{
			const char *errfunc = NULL;

			/* Hack: Fixup the SCTP socktype+protocol */
			if (protocol == IPPROTO_SCTP)
			{
				res->ai_socktype = SOCK_SEQPACKET;
				res->ai_protocol = IPPROTO_SCTP;
			}

			sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			if (sock != INVALID_SOCKET)
			{
				on = 1;
				setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
				on = 1;
				setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char *)&on, sizeof(on));

				if (res->ai_family == AF_INET6)
				{
					on = 1;
					setsockopt(sock, SOL_IPV6, IPV6_V6ONLY, &on, sizeof(on));
				}

				/* Bind to the correct address */
				if (bind(sock, res->ai_addr, (int)res->ai_addrlen) == 0)
				{
					/* Listen on the socket */
					if (res->ai_socktype == SOCK_DGRAM || listen(sock, LISTEN_QUEUE) == 0)
					{
						snprintf(buf, buflen, "Listening on %s://%s%s%s:%s (proto:%u, socktype:%s/%u)\n",
							res->ai_protocol == IPPROTO_UDP ? "udp" :
							(res->ai_protocol == IPPROTO_TCP ? "tcp" :
							(res->ai_protocol == IPPROTO_SCTP ? "sctp" : "??")),
							res->ai_family == AF_INET6 ? "[" : "",
							hostname ? hostname : (res->ai_family == AF_INET6 ? "::" : "."),
							res->ai_family == AF_INET6 ? "]" : "",
							service,
							res->ai_protocol,
							(res->ai_socktype == SOCK_STREAM ? "stream" :
							(res->ai_socktype == SOCK_DGRAM ? "datagram" :
							(res->ai_socktype == SOCK_SEQPACKET ? "seqpacket" : "unknown"))),
							res->ai_socktype);

						socketpool_add(pool, sock, tag, res->ai_family, res->ai_protocol, res->ai_socktype);
						count++;
					}
					else errfunc = "listen";
				}
				else errfunc = "bind";
			}
			else errfunc = "socket";

			/* Error? */
			if (errfunc)
			{
				struct sockaddr_in	res4;
				struct sockaddr_in6	res6;
				char			hst[42];

				if (res->ai_family == AF_INET) memcpy(&res4, res->ai_addr, sizeof(res4));
				else memcpy(&res6, res->ai_addr, sizeof(res6));

				inet_ntop(res->ai_family,
					res->ai_family == AF_INET ? (VOID *)&res4.sin_addr : (VOID *)&res6.sin6_addr,
					hst, sizeof(hst));

				snprintef(buf, buflen, errno, "Couldn't %s() on %s for %s://%s%s%s:%s (%s:%u)\n",
					errfunc,
					hst,
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

				if (sock != INVALID_SOCKET)
				{
					closesocket(sock);
					sock = INVALID_SOCKET;
				}
			}

			res = res->ai_next;
		}

		freeaddrinfo(ressave);
	}

	if (count == 0)
	{
		snprintef(buf, buflen, errno, "listen setup: socket error: could not open a socket of %s:%s over %s (%u) using protocol: %s (%u) sockettype: %s (%u)\n",
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

	return count;
}

static BOOL uri_parse_host(char *buf, unsigned int buflen, const char *uri, char *host, size_t len);
static BOOL uri_parse_host(char *buf, unsigned int buflen, const char *uri, char *host, size_t len)
{
	const char	*u = uri, *s;
	size_t		i;

	/* Zero out */
	memzero(host, len);

	/* Substract one because of the trailing \0 */
	len--;

	/* Literal IPv6 address notation? (RFC2732) */
	if (*u == '[')
	{
		/* skip the '[' marker and find the next, closing, one ']' */
		u++;
		s = strchr(u, ']');
		if (!s)
		{
			snprintf(buf, buflen, "Literal IPv6 address was not terminated in '%s'\n", uri);
			return false;
		}

		/* copy the string */
		i = s-u;
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
			i = !s ? len : i;
		}
		else
		{
			i = s-u;
		}
	}

	if (i >= len)
	{
		snprintf(buf, buflen, "Hostname too long in %s\n", uri);
		return false;
	}

	/* Copy the host */
	strncpy(host, u, i);

	return true;
}

static BOOL uri_parse_service(const char *uri, char *service, size_t len);
static BOOL uri_parse_service(const char *uri, char *service, size_t len)
{
	const char	*u = uri;
	char 		*s;
	size_t		i;

	/* Zero out */
	memzero(service, len);

	/* Substract one because of the trailing \0 */
	len--;

	/* Check for a port number */
	s = strchr(u, ':');
	if (!s) return false;

	u = s+1;
	/* Find the end */
	s = strchr(u, '/');
	i = s-u;
	if (!s || i < len) strncpy(service, u, !s ? len : i);

	return true;
}


/* Parse a URI and return the username and password */
BOOL parse_userpass(const char *uri, char *username, size_t username_len, char *password, size_t password_len)
{
	/* 's' = start of the username
	 * 'm' = end of the username and/or begin of password
	 * 'u' = end of password or username
	 * 'e' = tmp
	 */
	const char *s = uri, *u = NULL, *m = NULL;
	size_t e;

	/* Clear the return values */
	if (username) memzero(username, username_len);
	if (password) memzero(password, password_len);

	/* Skip the protocol declaration */
	s = strstr(uri, "://");
	/* If it doesn't have a protocol, fail */
	if (!s) return false;
	s += 3;

	/* Try to find a colon */
	m = strchr(s, ':');

	/* Now find the '@' sign which delimits to the host */
	u = strchr(s, '@');
	/* If it doesn't include a host, fail */
	if (!u) return false;

	/* if the ':' is after the '@' it is a port and there is no password */
	if (m && m > u) m = NULL;

	/* Copy the username */
	if (m) e = m - s;
	else e = u - s;
	if (username) memcpy(username, s, username_len < e ? username_len : e);

	/* Copy the password if any */
	if (m)
	{
		e = u - m - 1;
		if (password) memcpy(password, m + 1, password_len < e ? password_len : e);
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
 *  tcp://localhost:telnet
 *  udp6://[::1]:9084
 *  unix:///tmp/sixxsd.socket
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
static SOCKET use_uriA(char *buf, unsigned int buflen, BOOL doconnect, const char *uri, const char *defaultservice, struct socketpool *pool, uint32_t tag);
static SOCKET use_uriA(char *buf, unsigned int buflen, BOOL doconnect, const char *uri, const char *defaultservice, struct socketpool *pool, uint32_t tag)
{
	char		host[NI_MAXHOST], service[NI_MAXSERV], *hostname = host,
			bind_host[NI_MAXHOST], bind_service[NI_MAXSERV];
	const char	*u = uri, *s;
	int		family = AF_UNSPEC, socktype = 0, protocol = 0;

	/* Empty the host & service */
	memzero(host, sizeof(host));
	memzero(service, sizeof(service));
	memzero(bind_host, sizeof(bind_host));
	memzero(bind_service, sizeof(bind_service));

	/* Default to the defaultservice */
	if (defaultservice)
	{
		if (strlen(defaultservice) > (sizeof(service) - 1))
		{
			snprintf(buf, buflen, "Default service name is longer than NI_MAXSERV\n");
			return INVALID_SOCKET;
		}
	}

	/* Determine the socktype + protocol */
	if (strncmp(uri, "tcp://", 6) == 0)
	{
		socktype = SOCK_STREAM;
		protocol = IPPROTO_TCP;
		u+=6;
	}
	else if (strncmp(uri, "tcp4://", 7) == 0)
	{
		family = AF_INET;
		socktype = SOCK_STREAM;
		protocol = IPPROTO_TCP;
		u+=7;
	}
	else if (strncmp(uri, "tcp6://", 7) == 0)
	{
		family = AF_INET6;
		socktype = SOCK_STREAM;
		protocol = IPPROTO_TCP;
		u+=7;
	}
	else if (strncmp(uri, "udp://", 6) == 0)
	{
		socktype = SOCK_DGRAM;
		protocol = IPPROTO_UDP;
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
		protocol = IPPROTO_UDP;
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
	else if (strncmp(uri, "unix://", 7) == 0)
	{
		family = AF_UNIX;
		socktype = SOCK_DGRAM;
		protocol = 0;
		u+=7;
	}
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
	else if (strncmp(uri, "file://", 7) == 0)
	{
		snprintf(buf, buflen, "file:// is not supported by connect_client()\n");
		return INVALID_SOCKET;
	}
	else
	{
		snprintf(buf, buflen, "URI '%s' doesn't contain a valid protocol\n", uri);
		return INVALID_SOCKET;
	}

	/* Skip the format, if there is one */
	s = strchr(u, '@');
	if (s) u = s+1;

	/* For AF_UNIX the rest is the path to the socket */
	if (family == AF_UNIX)
	{
		size_t i = strlen(u);
		if (i < (sizeof(host)-1)) strncpy(host, u, i);
		else
		{
			snprintf(buf, buflen, "UNIX path is too long\n");
			return INVALID_SOCKET;
		}
	}
	/* Handle TCP/UDP/SCTP which have a host[:port] notation */
	else
	{
		if (!uri_parse_host(buf, buflen, u, host, sizeof(host)))
		{
			snprintf(buf, buflen, "Could not parse host in URI '%s'\n", uri);
			return INVALID_SOCKET;
		}

		/* Did we find the mandatory host? */
		if (strlen(host) == 0)
		{
			snprintf(buf, buflen, "No host specified in URI '%s'\n", uri);
			return INVALID_SOCKET;
		}

		/* Skip past the host */
		u+=strlen(host);

		/* any host? (eg all://any:2055) */
		if (strcasecmp("any", host) == 0) hostname = NULL;

		/* Parse the service */
		if (!uri_parse_service(u, service, sizeof(service)))
		{
			snprintf(buf, buflen, "No service found in URI '%s', defaulting service to '%s'\n", uri, defaultservice);
			strncpy(service, defaultservice, sizeof(service) - 1);
		}

		/* Check if there is a bind option after this */
		s = strstr(u, "bind=");
		if (s)
		{
			/* Skip the 'bind=' */
			u = s + 5;

			/* Parse the service */
			if (!uri_parse_host(buf, buflen, u, bind_host, sizeof(bind_host)))
			{
				snprintf(buf, buflen, "Could not parse bind host in URI '%s'\n", uri);
				return INVALID_SOCKET;
			}

			/* Skip past the bind_host */
			u+=strlen(bind_host);

			/* Parse the service */
			if (!uri_parse_service(u, bind_service, sizeof(bind_service)))
			{
				snprintf(buf, buflen, "Could not parse bindservice in URI '%s'\n", uri);
				return INVALID_SOCKET;
			}
		}
	}

	/* Try to connect to the client or listen as a server using these values */
	return doconnect ?
		sock_connect(buf, buflen, hostname, service[0] == '\0' ? NULL : service, family, socktype, protocol,
			strlen(bind_host) == 0 ? NULL : bind_host,
			strlen(bind_service) == 0 ? NULL : bind_service) :
		sock_listen(buf, buflen, hostname, service[0] == '\0' ? NULL : service, family, socktype, protocol, pool, tag);
}

/* Split the URI up into multiple segments (separated by a space) and feed it to use_uriA */
SOCKET use_uri(char *buf, unsigned int buflen, BOOL doconnect, const char *uri, const char *defaultservice, struct socketpool *pool, uint32_t tag)
{
	size_t	fields = countfields(uri), i = 0;
	char	val[256];
	SOCKET	ret = 0;

        for (i = 1; i <= fields; i++)
        {
                if (!copyfield(uri, i, val, sizeof(val)) || strlen(val) == 0) continue;
		ret += use_uriA(buf, buflen, doconnect, val, defaultservice, pool, tag);

		/*
		 * For a connect, just pick the first one
		 * Thus passing an array of url's to a connect will use the first one that works
		 */
		if (doconnect && ret >= 0) break;
	}
	return ret;
}

int sock_printf(SOCKET sock, const char *fmt, ...)
{
	char	buf[1024];
	int	k;

	va_list ap;
	va_start(ap, fmt);
	k = vsnprintf(buf, sizeof(buf), fmt, ap);
	if (snprintfok(k, sizeof(buf))) send(sock, buf, k, MSG_NOSIGNAL);

	return 0;
}

/*
 * Read a line from a socket and store it in ubuf
 * Note: uses internal caching, this should be the only function
 * used to read from the sock! The internal cache is rbuf.
 */
int sock_getline(SOCKET sock, char *rbuf, uint64_t rbuflen, uint64_t *filled, char *ubuf, uint64_t ubuflen)
{
	uint64_t	j;
	int		i;

	/* A closed socket? -> clear the buffer */
	if (sock == INVALID_SOCKET)
	{
		memzero(rbuf, rbuflen);
		*filled = 0;
		return INVALID_SOCKET;
	}

	/* Clear the caller supplied buffer, just in case */
	memzero(ubuf, ubuflen);

	for (;;)
	{
		DD(ddolog("common", "gl() - Filled %" PRIu64 "\n", *filled);)

		/* Did we still have something in the buffer? */
		if (*filled > 0)
		{
			DD(ddolog("common", "gl() - Seeking newline (filled %" PRIu64 ")\n", *filled);)

			/* Walk to the end or until we reach a \n */
			for (j=0; (j < (*filled-1)) && (rbuf[j] != '\n'); j++);

			DD(ddolog("common", "gl() - Seeking newline - end\n");)

			/* Did we find a newline? */
			if (rbuf[j] == '\n')
			{
				DD(ddolog("common", "gl() - Found newline at %" PRIu64 "\n", j);)

				if (j > ubuflen)
				{
					/* Line too long */
					*filled = 0;
					dolog(LOG_ERR, "common", "Line Buffer almost flowed over without receiving a newline (j=%" PRIu64 ", ubuflen=%" PRIu64 ")\n", j, ubuflen);
					return INVALID_SOCKET;
				}

				/* Newline with a Linefeed in front of it ? -> remove it */
				if (rbuf[j] == '\n' && j >= 1 && rbuf[j-1] == '\r')
				{
					DD(ddolog("common", "gl() - Removing LF\n");)
					if (j>0) j--;
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
				if (*filled > j) *filled -= j;
				else *filled = 0;

				/* Now move the rest of the buffer to the front */
				if (*filled > 0) memmove(rbuf, &rbuf[j], *filled);
				else *filled = 0;

				DD(ddolog("common", "getline() - \"%s\", len = %" PRIu64 "\n", ubuf, j);)

				/* We got ourselves a line in 'buf' thus return to the caller */
				return strlen(ubuf);
			}
		}

		DD(ddolog("common", "gl() - Trying to receive...\n");)

		/* Fill the rest of the buffer */
		i = recv(sock, &rbuf[*filled], rbuflen - (*filled + 10), 0);

		DD(ddoelog("common", errno, "gl() - Received %d\n", i);)

		/* Orderly shutdown */
		if (i == 0) return INVALID_SOCKET;

		/* Fail on errors */
		if (i < 0)
		{
			if (errno == EAGAIN)
			{
				DD(ddolog("common", "gl() - Try Again / Would block\n");)
				return 0;
			}

			/* Fail */
			return INVALID_SOCKET;
		}

		/* We got more filled space! */
		*filled += i;

		/* Buffer overflow? */
		if (*filled > (rbuflen-10))
		{
			dolog(LOG_ERR, "common", "Buffer almost flowed over without receiving a newline (filled=%" PRIu64 ", rbuflen=%" PRIu64 ")\n", *filled, rbuflen);
			return INVALID_SOCKET;
		}

		/* And try again in this loop ;) */
	}

	/* Never reached */
	return INVALID_SOCKET;
}

/* Count the number of fields in <s> */
size_t countfields(const char *s)
{
	size_t	n = 1, i, p = 0;
	BOOL	quoted = false;

	if (s == NULL || strlen(s) == 0) return 0;

	for (i=0; s[i] != '\0'; i++)
	{
		/* See double quotes as one field */
		if (s[i] == '"') quoted = !quoted;

		/* (Multiple consecutive) spaces and tabs are a field split */
		else if (!quoted && (s[i] == ' ' || s[i] == '\t'))
		{
			/* Previous char didn't cause a jump to the next field? */
			if (i != p-1) n++;

			/* Our last whitespace */
			p = i;
		}
	}

	/* Only whitespace at the end */
	if (p == (i-1)) n--;

	return n;
}

/*
 * Copy <count> fields starting with <n> of string <s> into <buf> with a maximum of buflen
 *
 *      1            2               3               4    5
 * +---------+    +-----+  +--------------------+  +---+ +--+
 * |         |    |     |  |                    |  |   | |  |
 * ----------------------------------------------------------
 * The chicken\t\tcrossed "the road to get to the" other side
 * ----------------------------------------------------------
 *
 * begin = begin of the fields
 * field = first field we want copied
 * count = number of fields to copy
 * s     = source string
 * buf   = target string
 * i     = current offset
 * n     = current field
 * o     = offset in target buffer
 * c     = number of fields left to copy
 * 
 */
BOOL copyfields(const char *s, size_t field, size_t count, char *buf, size_t buflen)
{
	BOOL		quoted = false;
	unsigned int	i = 0, begin = 0, n = 0, o = 0;
	size_t		c = count;

	if (s == NULL || strlen(s) == 0) return false;

	/* Clear the buffer */
	memzero(buf, buflen);

	for (i=0; s[i] != '\0'; i++)
	{
		/* See double quotes as one field */
		if (s[i] == '"') quoted = !quoted;

		/* Find the next delimiter (space or tab) */
		else if (!quoted && (s[i] == ' ' || s[i] == '\t'))
		{
			/* Our next field */
			n++;

			/* Is this field in range? */
			if (n >= field)
			{
				/* Determine starts in the buffer */
				if (s[begin] == '"') begin++;
				if (o > 0) buf[o++] = ' ';

				/* Don't overflow :) */
				if ((i-begin) > (buflen - o)) return false;

				/* Copy the field */
				memcpy(&buf[o], &s[begin], i-begin);
				o+=(i-begin);

				/* Count of number of fields to copy */
				c--;
			}

			/* Skip over the next whitespace */
			for (;s[i] != '\0' && (s[i] == ' ' || s[i] == '\t'); i++);
			begin = i;
			i--;

			/* Stop processing when we have all the fields */
			if (c == 0 && count != 0) break;
		}
	}

	/* Still need to copy fields, or copy all (count == 0)? */
	if (c > 0 || count == 0)
	{
		if (s[begin] == '"')
		{
			begin++;
			if (i > 1 && s[i-2] == '"') i--;
		}
		if (o > 0) buf[o++] = ' ';
		if ((i-begin) > (buflen - o)) return false;
		memcpy(&buf[o], &s[begin], i-begin);
		o+=(i-begin);
	}

	if (o > 0 && (buf[o-1] == '"' || buf[o-1] == ' ')) o--;
	buf[o] = '\0';
	if ((buflen-o) > 0) memzero(&buf[o], buflen-o);

	return o == 0 ? false : true;
}


/* Not the most efficient but works */
BOOL findfield(const char *s, const char *f)
{
	size_t	fields = countfields(s), i;
	char	buf[100];

	for (i = 0; i < fields; i++)
	{
		if (!copyfields(s, i, 1, buf, sizeof(buf))) return false;
		if (strcasecmp(f,s) == 0) return true;
	}
	return false;
}

/* Generic boolean parser */
BOOL isyes(const char *buf)
{
	return (strcasecmp(buf, "yes") == 0 ||
		strcasecmp(buf, "true") == 0 ||
		strcasecmp(buf, "on") == 0 ||
		strcasecmp(buf, "enabled") == 0 ||
		strcasecmp(buf, "female") == 0 ||
		strcasecmp(buf, "1") == 0) ? true : false;
}

/*
 * 0          1     
 * 01234567 89012345
 * +----------------
 *            ffabcd	::ffff:aa.bb.cc.dd = IPv4 mapped
 */
BOOL isipv4(const IPADDRESS *a)
{
	uint64_t *a64 = (uint64_t *)a->a8;
	uint16_t *a16 = (uint16_t *)a->a8;

	/* Quick test, bits 80-96 must be 1 (11+12 == 0xffff) for it to be IPv4 */
	if (a->a8[10] != 0xff || a->a8[11] != 0xff) return false;

	/* Check the first 80 bits to be 0, otherwise it is IPv6 anyway */
	/* First 64 bits + bits 64-80 */
	if (a64[0] != 0 || a16[4] != 0) return false;

	/* Passed all tests, must be IPv4 (-Mapped IPv6 Address) */
	return true;
}

BOOL isunspecified(const IPADDRESS *a)
{
	return (a->a64[0] == 0 && a->a64[1] == 0) ? true : false;
}

/*
 * IP Version and prefix length aware edition of inet_ntop() and inet_pton()
 */
const char *inet_ntopA(const IPADDRESS *addr, char *dst, socklen_t cnt)
{
	if (isipv4(addr)) inet_ntop(AF_INET, (char *)&addr->a8[12], dst, cnt);
	else inet_ntop(AF_INET6, (char *)addr, dst, cnt);

	return dst;
}

const char *inet_ntopAL(const IPADDRESS *addr, unsigned int len, char *dst, socklen_t cnt)
{
	unsigned int l;

	if (isipv4(addr)) inet_ntop(AF_INET, (char *)&addr->a8[12], dst, cnt);
	else inet_ntop(AF_INET6, (char *)addr, dst, cnt);

	l = strlen(dst);

	snprintf(&dst[l], cnt-l, "/%u", len);

	return dst;
}

int inet_ptonA(const char *src, IPADDRESS *dst, unsigned int *length)
{
	char		tmp[1024];
	unsigned int	af, ret, i;

	/* Clear it out */
	memzero(dst, sizeof(*dst));

	/* Unspecified address, return Marc's favourite number */
	if (strcasecmp(src, "unspecified") == 0)
	{
		if (length) *length = 0;
		return 17;
	}

	/* When it includes a ':' it is an IPv6 address */
	af = strstr(src, ":") ? AF_INET6 : AF_INET;

	/* Copy the address till the end or '/' */
	memzero(tmp, sizeof(tmp));
	for (i=0; i < 1024 && src[i] != '\0' && src[i] != '/'; i++) tmp[i] = src[i];
	if (i >= 1024)
	{
		errno = ENOSPC;
		return -1;
	}

	/* Parse the address */
	ret = inet_pton(af, tmp, dst->a8);
	if (ret <= 0) return ret;

	/* Move IPv4 address to the back and set the ::ffff in front of it */
	if (af == AF_INET)
	{
		memcpy(&dst->a8[12], &dst->a8[0], 4);
		memcpy(&dst->a8[0], ipv4_mapped_ipv6_prefix, sizeof(ipv4_mapped_ipv6_prefix));
	}

	/* Return an optionally given prefixlength? */
	if (length)
	{
		unsigned int	l;
		char		*s;

		/* Prefix length given? */
		s = index(src, '/');

		if (s)
		{
			/* Don't allow negativity */
			if (s[1] == '-')
			{
				errno = ENOMSG;
				return -1;
			}

			/* Get the length from behind the number */
			if (sscanf(&s[1], "%u", &l) != 1)
			{
				errno = EDOM;
				return -1;
			}

			/* Add 96 bits as that is where IPv4 starts inside IPv6 */
			/* Users specify a /24, but then it is a /120 to us */
			/* Only do this when it is not a /0 and when it is IPv4 */
			if (l != 0 && af == AF_INET) l += 96;
		}
		/* No Prefix length, thus a /128 */
		else l = 128;

		/* Make sure that the prefix length is valid */
		if (l > 128)
		{
			errno = EMSGSIZE;
			return -1;
		}

		*length = l;
	}

	return ret;
}

/*
 * Get Socket Name for local or peer
 * Fixes up IPv4 mapped ::ffff:x.x.x.x and compatible (::x.x.x.x) IPv6 addresses so that
 * we handle them correctly as IPv4 and not IPv6, which they are not.
 * Returns the family of the thing.
 */
VOID sock_cleanss(struct sockaddr_storage *ss)
{
	if (	ss->ss_family == AF_INET6 &&
		isipv4((const IPADDRESS *)&((struct sockaddr_in6 *)ss)->sin6_addr))
	{
		/* Move the IPv4 address into the correct place */
		memmove(	&((struct sockaddr_in *)ss)->sin_addr,
				(char *)(&((struct sockaddr_in6 *)ss)->sin6_addr)+12, 4);

		/* It's IPv4 now */
		ss->ss_family = AF_INET;
	}
}

#define LISTEN_QUEUE    128

VOID socketpool_init(struct socketpool *pool)
{
	FD_ZERO(&pool->fds);
	pool->hi = 0;
	List_New(&pool->sockets);
}

VOID socketpool_exit(struct socketpool *pool)
{
	struct socketnode *sn, *sn2;

	if (!pool) return;

	/* Remove all the sockets in the pool */
	List_For(&pool->sockets, sn, sn2, struct socketnode *)
	{
		socketpool_remove(pool, sn);
		mfree(sn, "socketnode", sizeof(*sn));
	}
}

struct socketnode *socketpool_accept(struct socketpool *pool, struct socketnode *sn_a, unsigned int tag)
{
	struct sockaddr_storage	sa;
	socklen_t		addrlen = sizeof(sa);
	struct socketnode	*sn;

	SOCKET sock = accept(sn_a->socket, (struct sockaddr *)&sa, &addrlen);

	/* Directly return on failures */
	if (sock < 0)
	{
		dolog(LOG_ERR, "common", "Couldn't accept a new client with tag %u\n", tag);
		return NULL;
	}

	/* Add the client to the pool */
	sn = socketpool_add(pool, sock, tag, sn_a->family, sn_a->protocol, sn_a->socktype);

	ddolog("common", "Accepted %" PRIu64 " with tag %u\n", sn->socket, tag);
	sn->lastrecv = gettime();
	return sn;
}

struct socketnode *socketpool_add(struct socketpool *pool, SOCKET sock, unsigned int tag, uint16_t family, uint16_t protocol, uint16_t socktype)
{
	struct socketnode	*sn;

	/* Allocate space for a new socketnode */
	sn = mcalloc(sizeof(*sn), "socketnode");
	if (!sn)
	{
		doelog(LOG_ERR, errno, "common", "Couldn't allocate memory for socketnode\n");

		return NULL;
	}

	/* Socketnode */
	sn->socket = sock;
	sn->tag = tag;
	sn->family = family;
	sn->protocol = protocol;
	sn->socktype = socktype;

	/* Add the socket to the pool */
	List_AddTail(&pool->sockets, sn);

	/* Make select() aware of the socket */
	FD_SET(sock, &pool->fds);
	if (sock > pool->hi) pool->hi = sock;

	return sn;
}

VOID socketpool_remove(struct socketpool *pool, struct socketnode *sn)
{
	if (sn->socket != INVALID_SOCKET)
	{
		shutdown(sn->socket, SHUT_RDWR);
		closesocket(sn->socket);
		FD_CLR(sn->socket, &pool->fds);
	}

	/* Remove it from the socket list */
	List_Remove(sn);
}

/*
 * Read a line from a socket and store it in ubuf
 * Note: uses internal caching, this should be the only function
 * used to read from the sock! The internal cache is rbuf.
 */
static int sock_getdata(SOCKET sock, char *rbuf, uint64_t rbuflen, uint64_t *filled);
static int sock_getdata(SOCKET sock, char *rbuf, uint64_t rbuflen, uint64_t *filled)
{
	int i;

	/* A closed socket? -> clear the buffer */
	if (sock == INVALID_SOCKET)
	{
		memzero(rbuf, rbuflen);
		*filled = 0;
		return -1;
	}

	/* Fill the rest of the buffer */
	i = recv(sock, &rbuf[*filled], rbuflen - *filled - 10, 0);

	/* Fail on errors */
	if (i <= 0) return -1;

	/* We got more filled space! */
	*filled += i;

	/* Buffer overflow? */
	if (*filled >= (rbuflen-10))
	{
		dolog(LOG_ERR, "common", "Buffer almost flowed over\n");
		return -1;
	}

	return *filled;
}

static size_t sock_done(SOCKET UNUSED sock, char *rbuf, size_t UNUSED rbuflen, uint64_t *filled, uint64_t amount);
static size_t sock_done(SOCKET UNUSED sock, char *rbuf, size_t UNUSED rbuflen, uint64_t *filled, uint64_t amount)
{
	/* Done with this part */
	*filled -= amount;

	/* Move the leftovers to the front */
	memmove(rbuf, &rbuf[amount], *filled);
	
	return *filled;
}

uint64_t sn_dataleft(struct socketnode *sn)
{
	return sn->filled;
}

int sn_getdata(struct socketnode *sn)
{
	return sock_getdata(sn->socket, sn->buf, sizeof(sn->buf), &sn->filled);
}

uint64_t sn_done(struct socketnode *sn, uint64_t amount)
{
	return sock_done(sn->socket, sn->buf, sizeof(sn->buf), &sn->filled, amount);
}

int sn_getline(struct socketnode *sn, char *ubuf, uint64_t ubuflen)
{
	return sock_getline(sn->socket, sn->buf, sizeof(sn->buf), &sn->filled, ubuf, ubuflen);
}

int get_utc_offset(VOID)
{
	time_t		te, twee;
	struct tm	tweem;
	int		utc_offset;

	te = gettime();
	gmtime_r(&te, &tweem);
	twee = mktime(&tweem);
	utc_offset = te - twee;

	/* Adjust for DST */
	if (tweem.tm_isdst) utc_offset += 3600;

	return utc_offset;
}

uint64_t gettime(VOID)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return ts.tv_sec;
}

uint64_t gettime_us(VOID)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);
}

#if defined(DEBUG) || defined(DEBUG_LOCKS) || defined(DEBUG_STACK)
#ifdef _LINUX
#include <execinfo.h>

VOID dump_stacktrace(VOID **trace, uint64_t *trace_size, unsigned int skip)
{
	int size = backtrace(trace, *trace_size);

	/* Always skip myself */
	skip++;

	if (size <= 0)
	{
		*trace_size = 0;
		return;
	}

	if ((unsigned int)size < skip)
	{
		*trace_size = 0;
		return;
	}

	memmove(trace, ((char *)trace) + (sizeof(*trace) * skip), sizeof(*trace) * (size - skip));
	*trace_size = (size - skip);
}

VOID format_stacktrace(char *buf, unsigned int length, VOID **trace, unsigned int trace_size)
{
	char		**messages = (char **)NULL;
	os_thread_id	tid = os_getthisthreadid();
	unsigned int	i = 0, o = 0, k;

	memzero(buf, length);

	messages = backtrace_symbols(trace, trace_size);
	if (!messages)
	{
		snprintf(buf, length, "[%p] %02u - Got trace, but could not generate messages\n", (VOID *)tid, i);
		return;
	}

	for (i=0; i < trace_size; i++)
	{
		k = snprintf(&buf[o], length-o, "[%p] %02u %s\n", (VOID *)tid, i, messages[i]);
		if (k > 0) o += k;
		else break;
	}

	free(messages);
}

VOID output_stacktrace(VOID)
{
	VOID		*trace[16];
	char		buf[4096];
	uint64_t	trace_size = lengthof(trace);

	dump_stacktrace(trace, &trace_size, 1);
	format_stacktrace(buf, sizeof(buf), trace, trace_size);
	fprintf(stddbg, "8<---------------------- stack:\n%s-------------------->8\n", buf);
	fflush(stddbg);
}

#else /* _LINUX */

VOID dump_stacktrace(VOID)
{
}
VOID format_stacktrace(VOID)
{
}
VOID output_stacktrace(VOID)
{
}
#endif
#endif

