/*****************************************************
 SixXSd - Common Functions
******************************************************
 $Author: jeroen $
 $Id: common.c,v 1.1 2004-08-30 19:33:45 jeroen Exp $
 $Date: 2004-08-30 19:33:45 $
*****************************************************/

#include "../sixxsd.h"
extern void sigusr1(int i);

// The listen queue
#define LISTEN_QUEUE    128

void dologA(int level, char *fmt, va_list ap)
{
	if (g_conf && g_conf->daemonize) vsyslog(LOG_LOCAL7|level, fmt, ap);
	else vprintf(fmt, ap);
}

void dolog(int level, char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	dologA(level, fmt, ap);
	va_end(ap);
}

void sock_printf(int sock, char *fmt, ...)
{
	char	buf[2048];
	int	len;

	va_list ap;
	va_start(ap, fmt);
	// When not a socket send it to the logs
	if (sock == -1) dologA(LOG_INFO, fmt, ap);
	else len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (sock != -1) write(sock, buf, len);
}

// Read a line from a socket and store it in ubuf
// Note: uses internal caching, this should be the only function
// used to read from the sock! The internal cache is rbuf.
int sock_getline(int sock, char *rbuf, int rbuflen, int *filled, char *ubuf, int ubuflen)
{
	int		len, i;

	// A closed socket? -> clear the buffer
	if (sock == -1)
	{
		memset(rbuf, 0, rbuflen);
		*filled = 0;
		return -1;
	}

	// Clear the caller supplied buffer, just in case
	memset(ubuf, 0, ubuflen);

	for (;;)
	{
		// dolog(LOG_DEBUG, "gl() - Filled %d\n", *filled);

		// Did we still have something in the buffer?
		if (*filled > 0)
		{
			// dolog(LOG_DEBUG, "gl() - Seeking newline\n");

			// Walk to the end or until we reach a \n
			for (i=0; (i < (*filled-1)) && (rbuf[i] != '\n'); i++);

			// dolog(LOG_DEBUG, "gl() - Seeking newline - end\n");

			// Did we find a newline?
			if (rbuf[i] == '\n')
			{
				// dolog(LOG_DEBUG, "gl() - Found newline at %i\n", i);

				// Newline with a Linefeed in front of it ? -> remove it
				if (rbuf[i] == '\n' && rbuf[i-1] == '\r')
				{
					// dolog(LOG_DEBUG, "gl() - Removing LF\n");
					i--;
				}
				// else dolog(LOG_DEBUG, "gl() - No LF\n");

				// Copy this over to the caller
				memcpy(ubuf, rbuf, i);

				// dolog(LOG_DEBUG, "gl() - Copied\n");

				// Count the \r if it is there
				if (rbuf[i] == '\r') i++;
				// Count the \n
				i++;

				// filled = what is left in the buffer
				*filled -= i;

				// Now move the rest of the buffer to the front
				if (*filled > 0) memmove(&rbuf, &rbuf[i], *filled);
				else *filled = 0;

				// dolog(LOG_DEBUG, "getline() - \"%s\", len = %i\n", ubuf, i);

				// We got ourselves a line in 'buf' thus return to the caller
				return i;
			}
		}

		// dolog(LOG_DEBUG, "gl() - Trying to receive...\n");

		// Fill the rest of the buffer
		i = recv(sock, &rbuf[*filled], rbuflen-*filled-10, 0);

		// D(dolog(LOG_DEBUG, "gl() - Received %d\n", i);)

		// Fail on errors
		if (i <= 0) return -1;

		// We got more filled space!
		*filled+=i;

		// Buffer overflow?
		if (*filled >= (rbuflen-10))
		{
			dolog(LOG_ERR, "Buffer almost flowed over without receiving a newline\n");
			return -1;
		}

		// And try again in this loop ;)
	}

	// Never reached
	return -1;
}

int huprunning()
{
	int pid;

	FILE *f = fopen(PIDFILE, "r");
	if (!f) return 0;
	fscanf(f, "%d", &pid);
	fclose(f);
	// If we can HUP it, it still runs
	return (kill(pid, SIGHUP) == 0 ? 1 : 0);
}

void savepid()
{
	FILE *f = fopen(PIDFILE, "w");
	if (!f) return;
	fprintf(f, "%d", getpid());
	fclose(f);

	dolog(LOG_INFO, "Running as PID %d\n", getpid());
}

void cleanpid(int i)
{
	// Ignore the signals, will exit here anyways
	signal(SIGTERM, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGKILL, SIG_IGN);

	// Dump the stats one last time
	sigusr1(SIGUSR1);

	// Remove the PID file
	unlink(PIDFILE);

	// Show the message in the log
	dolog(LOG_INFO, "Shutdown; Thank you for using SixXSd\n");

	// Close files and sockets
	fclose(g_conf->stat_file);
	
	// Free interfaces & prefixes
	free(g_conf->interfaces);
	free(g_conf->prefixes);

	// Free the config memory
	free(g_conf);

	exit(0);
}

int listen_server(const char *description, const char *hostname, const char *service, int family, int socktype)
{
	struct addrinfo	hints, *res, *ressave;
	int		n, sock;
	socklen_t	on = 1;
/*
	D(dolog(LOG_ERR, "[%s] Trying to get socket for [%s]:%s over %s (%d) using %s (%d)\n",
		description, hostname, service,
		family == AF_INET ? "IPv4" : (family == AF_INET6 ? "IPv6" : "??"),
		family,
		socktype == IPPROTO_UDP ? "UDP" : (socktype == IPPROTO_TCP ? "TCP" : "??"),
		socktype);)
*/
	memset(&hints, 0, sizeof(struct addrinfo));

	/* AI_PASSIVE flag: the resulting address is used to bind
 	   to a socket for accepting incoming connections.
	   So, when the hostname==NULL, getaddrinfo function will
  	   return one entry per allowed protocol family containing
	   the unspecified address for that family. */

	hints.ai_flags    = AI_PASSIVE;
	hints.ai_family   = family;
	hints.ai_socktype = socktype;

	n = getaddrinfo(hostname, service, &hints, &res);
	if (n < 0)
	{
		dolog(LOG_ERR, "[%s] listen_server setup: getaddrinfo error: %s\n", description, gai_strerror(n));
		return -1;
	}

	ressave=res;

	/* Try to open socket with each address getaddrinfo returned,
 	   until we get one valid listening socket. */
	sock = -1;
	while (res)
	{
		sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (!(sock < 0))
		{
			setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
			if (bind(sock, res->ai_addr, res->ai_addrlen) == 0) break;
			close(sock);
			sock = -1;
		}
		res = res->ai_next;
	}

	if (sock < 0)
	{
		freeaddrinfo(ressave);
		dolog(LOG_ERR, "[%s] listen setup: socket error: could not open socket\n", description);
		return -1;
	}

	listen(sock, LISTEN_QUEUE);

	dolog(LOG_INFO, "[%s] Listening on [%s]:%s\n", description, hostname, service);

	freeaddrinfo(ressave);
	return sock;
}

// Count the number of fields in <s>
unsigned int countfields(char *s)
{
	int n = 1, i;
	if (s == NULL) return 0;
	for (i=0; s[i] != '\0'; i++) if (s[i] == ' ') n++;
	return n;
}

// Copy field <n> of string <s> into <buf> with a maximum of buflen
// First field is 1
bool copyfield(char *s, unsigned int n, char *buf, unsigned int buflen)
{
	unsigned int begin = 0, i=0;

	// Clear the buffer
	memset(buf, 0, buflen);

	while (s[i] != '\0')
	{
		n--;
		begin = i;

		// Find next delimiter
		for (; s[i] != '\0' && s[i] != ' '; i++);

		if (n == 0)
		{
			i-=begin;
			strncpy(buf, s+begin, i > buflen ? buflen : i);
			// dolog(LOG_DEBUG, "copyfield() : '%s', begin = %d, len = %d\n", buf, begin, i);
			return true;
		}
		
		i++;
	}
	dolog(LOG_WARNING, "copyfield() - Field %u didn't exist in '%s'\n", n, s);
	return false;
}
