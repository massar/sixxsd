/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2012 All Rights Reserved
************************************************************
 SixXS Daemon main code
***********************************************************/

#include "sixxsd.h"
#include "common_extra.h"

const char module_sixxsd[] = "sixxsd";
#define module module_sixxsd

static VOID sighup(int i);
static VOID sighup(int i)
{
	struct sixxsd_thread *t;

	/* Ignore the signal, we might otherwise be in this function twice... */
	signal(i, SIG_IGN);

	t = thread_getthis();

	mdolog(LOG_INFO, "Received signal %d in %s/%u - shutting down%s\n", i, t ? t->description : "<unknown>", (unsigned int)(t ? t->thread_id : 0), g_conf && g_conf->running ? "" : " again");
	if (t && !t->start_routine)
	{

		/* Stop running */
		if (g_conf) g_conf->running = false;
	}

	/* Reset the signal */
	signal(i, sighup);
}

VOID terminate(const char *who)
{
	struct sixxsd_thread *t;

#ifdef DEBUG
	output_stacktrace();
	/* When debugging trap so that we can do a backtrace */
	assert(false);
#endif

	t = thread_getthis();
	mdolog(LOG_ERR, "Terminate() called by %s in %s, unsure of myself as I am in an invalid state, thus just exiting\n", who, t ? t->description : "<unknown>");
	exit(-42);
}

static VOID sigshutdown(int i);
static VOID sigshutdown(int i)
{
	struct sixxsd_thread *t;

	signal(i, SIG_IGN);

	if (g_conf) g_conf->running = false;

	t = thread_getthis();
	mdolog(LOG_ERR, "Received %s in %s - trying to gracefully shutdown\n", i == SIGBUS ? "SIGBUS" : i == SIGKILL ? "SIGKILL" : "SIGSEGV", t ? t->description : "<unknown>");
}

/* Handle illegal instruction */
static VOID sigill(int UNUSED i);
static VOID sigill(int UNUSED i)
{
	mdolog(LOG_ERR, "Illegal Processor Instruction caught, SixXSd was compiled with \"%s\"\n", SIXXSD_OPTIONS);
	terminate("sigill");
}

struct sixxsd_client
{
	struct sixxsd_context	ctx;		/* SixXSd handle */
	char			rbuf[16*1024];	/* Per client readbuffer */
	uint64_t		filled;		/* Amount of filled buffer */
};

/* The main command menu */
struct ctx_menu ctx_menu_main[13] =
{
	{"main",	NULL,			0,0,	NULL,		NULL },
	{"cmd",		ctx_cmd_cmd,		0,-1,	CONTEXT_SUB,	"Various Commands" },
	{"pop",		ctx_cmd_pop,		0,-1,	CONTEXT_SUB,	"PoP Commands" },
	{"subnet",	ctx_cmd_subnet,		0,-1,	CONTEXT_SUB,	"Subnet Commands" },
	{"tunnel",	ctx_cmd_tunnel,		0,-1,	CONTEXT_SUB,	"Tunnel Commands" },
	{NULL,		NULL,			0,0,	NULL,		NULL },
};

static PTR *sixxsd_handleclient_thread(PTR *lc_);
static PTR *sixxsd_handleclient_thread(PTR *lc_)
{
	struct sixxsd_client	*lc = (struct sixxsd_client *)lc_;
	fd_set			fd_select, fd_read;
	int			hifd = 0, i, timeouts = 0, ret;
	struct timeval		timeout;
	BOOL			close_socket = false, said_bye = false;
	char			line[1024];

	/* Let it block, we use select() and there is only one socket for this thread */
	sock_setblock(lc->ctx.socket);

	/* Add it to our select set so that we actually care about it */
	FD_ZERO(&fd_select);
	FD_SET(lc->ctx.socket, &fd_select);

	if (lc->ctx.socket > hifd) hifd = lc->ctx.socket;

	/* Introduce ourselves */
	ctx_printdf(&lc->ctx, "%s SixXSd %s by Jeroen Massar <jeroen@sixxs.net>\n", g_conf->pop_name, SIXXSD_VERSION);
	ctx_flush(&lc->ctx, 200);

	while (!close_socket && lc->ctx.socket != -1 && g_conf && g_conf->running)
	{
		/* What we want to know */
		memcpy(&fd_read, &fd_select, sizeof(fd_read));

		/* Timeout */
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;

		thread_setstate(thread_state_selectwait);
		i = select(hifd+1, &fd_read, NULL, NULL, &timeout);
		thread_setstate(thread_state_running);

		if (!g_conf || !g_conf->running) break;

		if (i < 0)
		{
			/* Ignore signals, appropriate flags will be set to handle them */
			if (errno == EINTR) continue;

			mdoelog(LOG_ERR, errno, "(%" PRIu64 ") Client select failed\n", lc->ctx.socket);
			break;
		}

		/* Timeout */
		if (i == 0)
		{
			timeouts++;
			if (timeouts < 180) continue;

			mdolog(LOG_WARNING, "(%" PRIu64 ") Client timed out after %u seconds, disconnecting\n", lc->ctx.socket, timeouts);
			ctx_printf(&lc->ctx, "Tschau, connection timed out\n");
			ctx_flush(&lc->ctx, 500);
			said_bye = true;
			break;
		}

		timeouts = 0;

		if (FD_ISSET(lc->ctx.socket, &fd_read))
		{
			/* Read some data */
			i = sock_getline(lc->ctx.socket, lc->rbuf, sizeof(lc->rbuf), &lc->filled, line, sizeof(line));
			if (i < 0 || !g_conf || !g_conf->running)
			{
				close_socket = true;
			}
			else
			{
				while (i > 0 && !close_socket && g_conf && g_conf->running)
				{
					/* Execute the command */
					ret = ctx_command(&lc->ctx, line);

					/* Flush the result to the client */
					ctx_flush(&lc->ctx, ret);

					/* Exit or another command? */
					if (ret == 666)
					{
						close_socket = said_bye = true;
					}
					else
					{
						i = sock_getline(lc->ctx.socket, lc->rbuf, sizeof(lc->rbuf), &lc->filled, line, sizeof(line));
					}
				}
			}
		}
	}

	if (!said_bye)
	{
		ctx_printf(&lc->ctx, "Tschau, closing down\n");
		ctx_flush(&lc->ctx, 404);
	}

	shutdown(lc->ctx.socket, SHUT_RDWR);
	closesocket(lc->ctx.socket);
	lc->ctx.socket = -1;

	ctx_exit(&lc->ctx);

	mfree(lc, "sixxsd_client", sizeof(*lc));
	return NULL;
}

static VOID mainloop(struct sixxsd_context *ctx, struct socketpool *pool);
static VOID mainloop(struct sixxsd_context *ctx, struct socketpool *pool)
{
	int			i;
	fd_set			fd_read;
	struct sixxsd_client	*lc = NULL;
	struct timeval		timeout;
	struct socketnode	*sn, *sn2;
	struct sockaddr_storage sa;
	socklen_t		sa_len;

	/* Make all the sockets nonblocking */
	List_For (&pool->sockets, sn, sn2, struct socketnode *)
	{
		sock_setnonblock(sn->socket);
	}

	while (g_conf && g_conf->running)
	{
		if (!g_conf->running) break;

		/* What we want to know */
		memcpy(&fd_read, &pool->fds, sizeof(fd_read));

		/* Timeout */
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;

		thread_setstate(thread_state_selectwait);
		i = select(pool->hi+1, &fd_read, NULL, NULL, &timeout);
		thread_setstate(thread_state_running);

		if (i < 0)
		{
			/* Ignore signals, appropriate flags will be set to handle them */
			if (errno == EINTR) continue;
			else
			{
				mdoelog(LOG_ERR, errno, "Select failed\n");
			}
			break;
		}

		if (!g_conf || !g_conf->running) break;

		List_For (&pool->sockets, sn, sn2, struct socketnode *)
		{
			if (!FD_ISSET(sn->socket, &fd_read)) continue;

			if (!lc) lc = mcalloc(sizeof(*lc), "sixxsd_client");
			if (!lc)
			{
				mdoelog(LOG_ERR, errno, "Out of memory when wanting to accept a client\n");
				/* Break out of the mainloop, hoping that the shutdown parts can still salvage some things */
				return;
			}

			/* Connection from external source, init ctx */
			ctx_init(&lc->ctx);

			/* Incoming connection */
			sa_len = sizeof(sa);
			lc->ctx.socket = accept(sn->socket, (struct sockaddr *)&sa, &sa_len);
			if (lc->ctx.socket == -1)
			{
				mdoelog(LOG_WARNING, errno, "Socket Accept failed\n");

				/* Close ctx */
				ctx_exit(&lc->ctx);
			}
			else
			{
				IPADDRESS	ip;
				unsigned int	j;
				char		buf[1024], hst[128];
				int		k;

				switch (sa.ss_family)
				{
				case AF_INET:
					ipaddress_make_ipv4(&ip, &((struct sockaddr_in *)&sa)->sin_addr);
					break;

				case AF_INET6:
					ipaddress_make_ipv6(&ip, &((struct sockaddr_in6 *)&sa)->sin6_addr);
					break;

				default:
					mdolog(LOG_ERR, "Unknown Address Family %u\n", sa.ss_family);
					break;
				}

				inet_ntopA(&ip, hst, sizeof(hst));

				/* Check ACL */
				for (j = 0; j < lengthof(g_conf->cli_acl); j++)
				{
					inet_ntopA(&g_conf->cli_acl[j], buf, sizeof(buf));
					if (memcmp(&g_conf->cli_acl[j], &ip, sizeof(ip)) != 0) continue;

					k = snprintf(buf, sizeof(buf), "Client (%s %s)",
						hst,
						sn->socktype == SOCK_DGRAM ? "DGRAM" :
							(sn->socktype == SOCK_SEQPACKET ? "SEQPACKET" :
							(sn->socktype == SOCK_STREAM ? "STREAM" : "UNKNOWN")));
					if (!snprintfok(k, sizeof(buf))) snprintf(buf, sizeof(buf), "Client (long)");

					if (thread_add(ctx, buf, sixxsd_handleclient_thread, (PTR *)lc, NULL, false))
					{
						/* Thread is running, thus make a new lc in the next loop */
						lc = NULL;
						break;
					}
					else
					{
						mdoelog(LOG_WARNING, errno, "Could not create a new thread\n");

						/* CLose the context, reuse the lc in the next loop */
						ctx_exit(&lc->ctx);
						break;
					}
				}

				if (j >= lengthof(g_conf->cli_acl))
				{
					/* Not in the ACL - give the little hax0r only a bit of info :) */
					sock_printf(lc->ctx.socket, "HTTP/1.1 301 Content Moved\n");
					sock_printf(lc->ctx.socket, "Date: Sat, 25 Feb 1978 06:06:06\n");
					sock_printf(lc->ctx.socket, "Server: SixXSd\n");
					sock_printf(lc->ctx.socket, "Location: http://www.sixxs.net/\n");
					sock_printf(lc->ctx.socket, "Content-Type: text/html\n");
					sock_printf(lc->ctx.socket, "\n");
					sock_printf(lc->ctx.socket, "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n");
					sock_printf(lc->ctx.socket, "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n");
					sock_printf(lc->ctx.socket, "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">\n");
					sock_printf(lc->ctx.socket, "<head>\n");
					sock_printf(lc->ctx.socket, "<title>SixXSd</title>\n");
					sock_printf(lc->ctx.socket, "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\" />\n");
					sock_printf(lc->ctx.socket, "</head>\n");
					sock_printf(lc->ctx.socket, "\n");
					sock_printf(lc->ctx.socket, "<body>\n");
					sock_printf(lc->ctx.socket, "Information about SixXS can be found on the <a href=\"http://www.sixxs.net/\">SixXS website</a>.\n");
					sock_printf(lc->ctx.socket, "</body>\n");
					sock_printf(lc->ctx.socket, "</html>\n");

					sock_printf(lc->ctx.socket, "<!-- Your IP: %s -->\n", hst);

					/* Cleanup */
					ctx_exit(&lc->ctx);
				}
			}
		}

	}

	if (lc)
	{
		ctx_exit(&lc->ctx);
		mfree(lc, sizeof(*lc), "sixxsd_client");
		lc = NULL;
	}

	socketpool_exit(pool);
}

static VOID welcome(VOID);
static VOID welcome(VOID)
{
	mdolog(LOG_NOTICE, "%s %s\n", SIXXSD_DESC, SIXXSD_VERSION);
	mdolog(LOG_NOTICE, "SixXSd %s by Jeroen Massar <jeroen@sixxs.net>\n", SIXXSD_RELEASE);

	/* Show the copyright line */
	mdolog(LOG_NOTICE, "%s\n", SIXXSD_COPYRIGHT);
}

static int sixxsd_run(struct sixxsd_context *ctx);
static int sixxsd_run(struct sixxsd_context *ctx)
{
	struct socketpool	pool;
	struct sixxsd_thread	*t;
	char			buf[1024];

	memzero(buf, sizeof(buf));

	/* Register the main thread (this) */
	thread_add(ctx, "SixXSd", NULL, NULL, &t, false);

	/* Open the URI */
	socketpool_init(&pool);
	if (use_uri(buf, sizeof(buf), false, "any://any:42003", "42003", &pool, 42) == 0)
	{
		if (strlen(buf) > 0) ctx_printf(ctx, "%s", buf);
		ctx_printef(ctx, errno, "Error while trying to open the SixXS socket\n");
	}
	else
	{
		if (strlen(buf) > 0) ctx_printf(ctx, "%s", buf);
		while (true)
		{
			ctx_printf(ctx, "Running as PID %u\n", getpid());
			ctx_flush(ctx, 200);

			/* Do the mainloop */
			mainloop(ctx, &pool);

			mddolog("Mainloop exited, going down...\n");
			break;
		}
	}

	/* Remove our main thread */
	thread_remove(t, true);

	return 0;
}

#ifdef GOT_GETOPT_LONG
/* Long options */
static struct option const long_options[] = {
	{"daemonize",		no_argument,		NULL, 'd'},
	{"help",		no_argument,		NULL, 'h'},
	{"nodaemonize",		no_argument,		NULL, 'f'},
	{"silent",		no_argument,		NULL, 's'},
	{"verbose",		no_argument,		NULL, 'v'},
	{"version",		no_argument,		NULL, 'V'},
	{"helpme",		no_argument,		NULL, '?'},
	{NULL,			0,			NULL, 0},
};
#endif

char short_options[] = "c:dhfsvV?";

int main(int argc, char *argv[], char UNUSED *envp[]);
int main(int argc, char *argv[], char UNUSED *envp[])
{
	int			i, ret = 0;
	struct sixxsd_context	ctx;
#ifdef GOT_GETOPT_LONG
	int			option_index = 0;
#endif
	BOOL			cfg_daemonize;
	uint32_t		cfg_verbose = 0;

#ifdef DEBUG
	/* Make us very nice, as we are actually very nice */
	nice(19);

	cfg_daemonize = false;
#else
	cfg_daemonize = true;
#endif /* !_DEBUG */

	/* Handle a SIGHUP/SIGTERM/SIGINT to cleanly exit */
	signal(SIGHUP,	sighup);
	signal(SIGTERM,	sighup);
	signal(SIGINT,	sighup);

	/* Seed the randomization engine */
	srand(gettime() + 42);

	/* Handle arguments */
#ifdef GOT_GETOPT_LONG
	while ((i = getopt_long(argc, argv, short_options, long_options, &option_index)) != EOF)
#else
	while ((i = getopt(argc, argv, short_options)) != EOF)
#endif
	{
		switch (i)
		{
		case 'd':
			/* Daemonize into the background */
			cfg_daemonize = true;
			break;

		case 'f':
			/* stay in the Foreground */
			cfg_daemonize = false;
			break;

		case 'V':
			printf("Product: %s\n", SIXXSD_DESC);
			printf("Version: %s\n", SIXXSD_VERSION);
			printf("Release: %s\n", SIXXSD_RELEASE);
			return 0;

		case 'v':
			/* Verbose */
			cfg_verbose++;
			break;

		case 's':
			/* Silent */
			cfg_verbose = 0;
			break;

		default: /* Default to help for all unknown arguments */
			welcome();

			if (i != 'h' && i != '?') printf("Unknown option '%c'\n\n", i);

			printf( "%s [opts]\n", argv[0]);
			printf( "\n");
			printf( "-C, --commands                Output all the help pages\n");
			printf(	"-d, --daemonize               daemonize"
#ifndef DEBUG
				" (default)"
#endif
				"\n"
				"-f, --nodaemonize             don't daemonize"
#ifdef DEBUG
				" (default)"
#endif
				"\n");

			printf( "-V, --version                 show version information and abort\n"
				"-v, --verbose                 verbosely log messages, multiple for more verbosity"
#ifdef DEBUG
				" (default)"
#endif
				"\n"
				"-s, --silent                  only log important messages (reset verbose to off)"
#ifndef DEBUG
				" (default)"
#endif
				"\n");
			printf( "\n"
				"\n"
				"Please report bugs and problems to Jeroen Massar <jeroen@sixxs.net>.\n");

			/* Shown options, thus exit */
			return -1;
		}
	}

	/*
	 * Daemonize if wanted
	 * This needs to be done before calling *ANY* pthread_*() calls
	 * otherwise the fork messes it up quite badly ;)
	 */
	if (cfg_daemonize)
	{
		i = fork();
		if (i < 0)
		{
			mdoelog(LOG_ERR, errno, "Couldn't fork for daemonization\n");
			return -1;
		}
		/* Exit the mother fork */
		if (i != 0) return 0;

		/* Child fork in it's own program group */
		setsid();

		/* Cleanup stdin/out/err */
		freopen("/dev/null", "r", stdin);
		freopen("/dev/null", "w", stdout);
		freopen("/dev/null", "w", stderr);
	}

	/* Handle a SIGHUP/SIGTERM/SIGINT to cleanly exit */
	signal(SIGHUP,	sighup);
	signal(SIGTERM,	sighup);
	signal(SIGINT,	sighup);

	/* Ignore some odd signals */
	signal(SIGABRT,	SIG_IGN);
	signal(SIGUSR1,	SIG_IGN);
	signal(SIGUSR2,	SIG_IGN);
	signal(SIGPIPE,	SIG_IGN);

	/* signal(SIGCHLD, SIG_IGN); <-- required by wait() */
	signal(SIGSTOP, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	signal(SIGUSR1,	SIG_IGN);
	signal(SIGUSR2, SIG_IGN);

#ifndef DEBUG
	/* Bus Errors and Segfaults */
	signal(SIGBUS, sigshutdown);
	signal(SIGSEGV, sigshutdown);
	signal(SIGKILL,	sigshutdown);

	/*
	 * Just in case we compile a binary for a certain arch
	 * and the machine where it gets run on doesn't support it
	 */
	signal(SIGILL, sigill);
#endif

	while (true)
	{
		/* Init our context */
		ctx_init(&ctx);

		/* Init our configuration */
		ret = cfg_init(&ctx, cfg_verbose);
		if (ret != 200) break;

		if (cfg_daemonize) g_conf->daemonize = true;
		else g_conf->daemonize = false;

		/* Show the welcome text */
		welcome();

		/* Load configuration from disk */
		ret = ctx_exec(&ctx, "sixxsd.conf", false, NULL);

		if (ret != 200) ctx_printf(&ctx, "Loading configuration failed\n");
		ctx_flush(&ctx, ret);
		if (ret != 200) break;

		/* Fire up our packet capture */
		ret = iface_init(&ctx);
		if (ret != 200) ctx_printf(&ctx, "Starting Captures failed\n");
		ctx_flush(&ctx, ret);
		if (ret != 200) break;

		ret = tunnel_init(&ctx);
		if (ret != 200) ctx_printf(&ctx, "Tunnel Beat Check startup failed\n");
		ctx_flush(&ctx, ret);
		if (ret != 200) break;

		/* Run SixXSd, Run! */
		ret = sixxsd_run(&ctx);

		/* Show the message in the log */

		break;
	}

	if (ret != 0) ctx_flush(&ctx, ret);

	mddolog("Shutdown - Greetings from the Daemon of SixXS, Tschau!\n");

	iface_exit(&ctx);

	/* Make sure we are going down */
	g_conf->running = false;

	/* Make sure that all threads have ended */
	thread_exit();

	/* Exit the configuration */
	cfg_exit();

	/* No more things to log */
	ctx_exit(&ctx);

	return ret;
}

