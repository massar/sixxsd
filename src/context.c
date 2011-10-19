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

const char module_ctx[] = "ctx";
#define module module_ctx

int ctx_cmd_exit(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[]);
int ctx_cmd_exit(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[])
{
	/* You can check out anytime you like, but you can never leave. */
	ctx_printf(ctx, "Tschau\n");
	return 666;
}

int ctx_shell(struct sixxsd_context *ctx, const char *args)
{
	FILE	*pipein;
	char	buf[10*1024];

	/* Create one way pipe line with call to popen() */
	pipein = popen(args, "r");
	if (!pipein) return 406;

	/* Get all the output */
	while (fgets(buf, sizeof(buf), pipein)) ctx_printdf(ctx, "%s", buf);

	/* Close the pipe */
	pclose(pipein);

	return 200;
}

int ctx_cmd_loop(struct sixxsd_context *ctx, const unsigned int argc, const char *args[]);
int ctx_cmd_sub(struct sixxsd_context *ctx, const unsigned int argc, const char *args[]);
int ctx_cmd_load(struct sixxsd_context *ctx, const unsigned int argc, const char *args[]);

struct ctx_menu ctx_menu_cmd[] =
{
	{"cmd",		NULL,		0,0,	NULL, NULL },
	{"exit",	ctx_cmd_exit,	0,-1,	NULL, "Exit" },
	{"quit",	ctx_cmd_exit,	0,-1,	NULL, NULL },
	{NULL,		NULL,		0,0,	NULL, NULL },
};

CONTEXT_CMD(cmd)

VOID ctx_exit(struct sixxsd_context *ctx, BOOL iscopy)
{
	/* Nothing to cleanup, everything is a copy */
	if (iscopy) return;

	ctx_lock(ctx);

	/* Cleanup tunnels that are debugging */
	if (ctx->debugging_tunnels > 0)
	{
		unsigned int		tid;
		struct sixxsd_tunnels	*tuns = &g_conf->tunnels;
		struct sixxsd_tunnel	*tun;

		for (tid = 0; tid <= tuns->tunnel_hi; tid++)
		{
			tun = tunnel_grab(tid);

			if (tun->debug_ctx == ctx)
			{
				tun->debug_ctx = NULL;
				ctx->debugging_tunnels--;
				assert(g_conf->debugging > 0);
				g_conf->debugging--;
			}
		}
	}

	if (ctx->socket != INVALID_SOCKET) closesocket(ctx->socket);
	ctx->socket = INVALID_SOCKET;

	/* Cleanup buffer */
	if (ctx->buffersize && ctx->buffer) mfree(ctx->buffer, ctx->buffersize, "ctx_buffer");
	ctx->buffer = NULL;
	ctx->buffersize = 0;

	ctx_release(ctx);
}

struct sixxsd_context *ctx_new(VOID)
{
	struct sixxsd_context *ctx;

	ctx = mcalloc(sizeof(*ctx), "sixxsd_context");
	if (!ctx)
	{
		mdoelog(LOG_ERR, errno, "Couldn't create a new ctx\n");
		return NULL;
	}

	ctx_init(ctx);

	return ctx;
}

VOID ctx_free(struct sixxsd_context *ctx, BOOL iscopy)
{
	ctx_exit(ctx, iscopy);
	mfree(ctx, sizeof(*ctx), "sixxsd_context");
}

VOID ctx_init(struct sixxsd_context *ctx)
{
	assert(ctx);

	/* Clean */
	memzero(ctx, sizeof(*ctx));

	mutex_init(ctx->mutex);

	/* The possible output channels */
	ctx->socket = INVALID_SOCKET;

	/* Start in the buffer at 128 so we can prepend status codes etc */
	ctx->bufferfilled = 128;

	/* Buffer size starts out at zero, resize will resize it properly */
	ctx->buffersize = 0;
	ctx->buffer = NULL;
}

/* Add text to the buffer, caching it for later copy or printout using flush() */
VOID ctx_printedfA(struct sixxsd_context *ctx, int errnum, const char *fmt, va_list ap)
{
	unsigned int	size, j;
	int		i;

	if (!ctx)
	{
		mdologA(LOG_ERR, fmt, ap);
		return;
	}

	/* Take a quick guess that this should be enough */
	size = (strlen(fmt) + 512), j;

	ctx_lock(ctx);

	while (true)
	{
		/* Need extra space in our buffer? (Always have >4k spare) */
		if ((size + ctx->bufferfilled + (4*1024)) > ctx->buffersize)
		{
			char *newbuf;

			assert((ctx->buffer == NULL && ctx->buffersize == 0) || (ctx->buffer != NULL && ctx->buffersize != 0));

			size = (((((size + ctx->bufferfilled + (4*1024)) / (4*1024))) * (4*1024)) + (4*1024));
			newbuf = (char *)mrealloc((PTR *)ctx->buffer, size, ctx->buffersize);
			if (!newbuf)
			{
				mdoelog(LOG_ERR, errno, "Out of memory while trying to ctx make buffer a bit larger\n");
				ctx_release(ctx);
				return;
			}

			ctx->buffer = newbuf;
			ctx->buffersize = size;
		}

		/* How much bufferspace is left? */
		size = ctx->buffersize - ctx->bufferfilled - 1;

		/* First put the message text in a buffer */
		i = vsnprintf(&ctx->buffer[ctx->bufferfilled], size, fmt, ap);

		/* Did the print go succesful? */
		if (snprintfok(i, size))
		{
			ctx->bufferfilled += (size_t)i;
			break;
		}

		/* Apparently we need this much space */
		if (i <= 0)
		{
			mdoelog(LOG_ERR, errno, "Mysterious system error while trying to add to ctx buffer\n");
			ctx_release(ctx);
			return;
		}

		/* We will need at least this much space */
		size = i;
	}

	/* Append errno description? */
	if (errnum != 0)
	{
		/* Still some space left? Then add it */
		if (ctx->bufferfilled < (ctx->buffersize-64))
		{
			/* Add ": " overwriting the \n which has to be present */
			ctx->buffer[ctx->bufferfilled-1] = ':';
			ctx->buffer[ctx->bufferfilled] = ' ';
			ctx->buffer[ctx->bufferfilled+1] = '\0';

			errno = 0;
			strerror_r(errnum, &ctx->buffer[ctx->bufferfilled+1], ctx->buffersize - (ctx->bufferfilled+2));

			j = strlen(&ctx->buffer[128]) + 128;
			i = snprintf(&ctx->buffer[j], ctx->buffersize-j, " (errno %d)\n", errnum);
			if (snprintfok(i, ctx->buffersize - j))
			{
				ctx->bufferfilled = (j + (unsigned int)i);
			}
		}
	}

	ctx_release(ctx);
}

VOID ctx_printef(struct sixxsd_context *ctx, int errnum, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	ctx_printedfA(ctx, errnum, fmt, ap);
	va_end(ap);
}

VOID ctx_printf(struct sixxsd_context *ctx, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	ctx_printedfA(ctx, 0, fmt, ap);
	va_end(ap);
}

VOID ctx_printdf(struct sixxsd_context *ctx, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	ctx_printedfA(ctx, 0, fmt, ap);
	va_end(ap);
}

VOID ctx_printxfA(struct sixxsd_context *ctx, BOOL data, const char *fmt, va_list ap);
VOID ctx_printxfA(struct sixxsd_context *ctx, BOOL data, const char *fmt, va_list ap)
{
	const char	*s;
	char		buf[2048], c;
	unsigned int	i, j, k;
	int		l;
	BOOL		quotes = false;

	memzero(buf, sizeof(buf));

	for (i = j = 0; fmt[i] != '\0' && j < sizeof(buf); i++)
	{
		if (fmt[i] != '%')
		{
			buf[j++] = fmt[i];
			continue;
		}

		i++;

		/* We only handle %s, %c, %u and %d */
		switch(fmt[i])
		{
		case 's':
			s = va_arg(ap, char *);

			/* Don't escape our leading tabs */
			if (i == 1 && s[0] == '\t')
			{
				for (k=0; s[k] != '\0' && j < sizeof(buf); k++)
				{
					buf[j++] = s[k];
				}

				continue;
			}

			/* Try to find \t or space first */
			quotes = false;
			for (k=0; s[k] != '\0'; k++)
			{
				if (s[k] != '\t' && s[k] != ' ') continue;

				quotes = true;
				break;
			}

			if (quotes && j < sizeof(buf)) buf[j++] = '"';

			for (k=0; s[k] != '\0' && j < sizeof(buf)+1; k++)
			{
				if (quotes)
				{
					/* Escape '"' */
					if (s[k] == '"' || s[k] == '\\') buf[j++] = '\\';

					if (s[k] == '\r')
					{
						buf[j++] = '\\';
						buf[j++] = 'r';
						continue;
					}

					/* Escape \n */
					if (s[k] == '\n')
					{
						buf[j++] = '\\';
						buf[j++] = 'n';
						continue;
					}
				}

				buf[j++] = s[k];
			}

			if (quotes && j < sizeof(buf)) buf[j++] = '"';

			break;

		case 'c':
			/* Raw %s, that is without quoting */
			c = va_arg(ap, int);
			if (c != '\0') buf[j++] = c;
			break;

		case 'u':
			l = snprintf(&buf[j], sizeof(buf)-j, "%u", va_arg(ap, unsigned int));
			/* Break out when it was not good */
			if (l >= 0) j+=l;
			else j = sizeof(buf)+42;
			break;

		case 'd':
			l = snprintf(&buf[j], sizeof(buf)-j, "%d", va_arg(ap, int));
			/* Break out when it was not good */
			if (l >= 0) j+=l;
			else j = sizeof(buf)+42;
			break;

		default:
			/* Unknown */	
			buf[j++] = fmt[i];
			break;
		}
	}

	if (data) ctx_printdf(ctx, "%s", buf);
	else ctx_printf(ctx, "%s", buf);
}

VOID ctx_printxf(struct sixxsd_context *ctx, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	ctx_printxfA(ctx, false, fmt, ap);
	va_end(ap);
}

VOID ctx_printxdf(struct sixxsd_context *ctx, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	ctx_printxfA(ctx, true, fmt, ap);
	va_end(ap);
}

VOID ctx_flush(struct sixxsd_context *ctx, int code)
{
	int		codep = code / 100;
	unsigned int	lines = 0, i;
	char		buf[128];

	/* Nothing to flush when there is no buffer */
	if (!ctx->buffer) return;

	ctx_lock(ctx);

	/* Count how many lines we get */
	for (i=128; i < ctx->buffersize && ctx->buffer[i] != '\0'; i++)
	{
		if (ctx->buffer[i] == '\n') lines++;
	}

	if (lines > 1)
	{
		/* Append the code + OK */
		ctx_printf(ctx, "%u OK\n", code);

		/* Prepend "{2|3|4|5}01 <linecount>" (Hope it goes okay :)*/
		snprintf(buf, sizeof(buf), "%u01 %u\n", codep, lines);
	}
	else
	{
		/* Otherwise just prefix the code in front of the line (should work) */
		snprintf(buf, sizeof(buf), "%u ", code);
	}

	/* How long is the prefix? */
	i = strlen(buf);

	/* Prepend the status text */
	memcpy(&ctx->buffer[128-i], buf, i);

	/* Send the line(s) over the network */
	if (ctx->socket != INVALID_SOCKET) send(ctx->socket, &ctx->buffer[128-i], ctx->bufferfilled - 128 + i, MSG_NOSIGNAL);
	else fwrite(&ctx->buffer[128-i], ctx->bufferfilled - 128 + i, 1, stdout);

	memzero(ctx->buffer, ctx->buffersize);
	ctx->bufferfilled = 128;

	ctx_release(ctx);
}

int ctx_exec(struct sixxsd_context *ctx, const char *args, BOOL mainmenu, const char *precmd)
{
	unsigned int		i, j, k, lineno = 0, o;
	char			buf[2048];
	char			*addr;
	int			ret = 200;
	uint64_t		size;

	int			f;
	struct stat		st;

	f = open(args, O_RDONLY);
	if (f == -1)
	{
		ctx_printef(ctx, errno, "Could not open file '%s'\n", args);
		return 406;
	}

	if (fstat(f, &st) == -1)
	{
		ctx_printef(ctx, errno, "Could not get size of '%s'\n", args);
		close(f);
		return 406;
	}

	size = st.st_size;

	addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE|MAP_POPULATE, f, 0);
	if (addr == MAP_FAILED)
	{
		ctx_printef(ctx, errno, "Could not mmap file '%s'\n", args);
		close(f);
		return 406;
	}

	if (precmd)
	{
		/* What goes in front + space */
		memzero(buf, sizeof(buf));
		strncat(buf, precmd, sizeof(buf));
		strncat(buf, " ", sizeof(buf));
		o = strlen(buf);
	}
	else o = 0;

	/* They expect to be running from the root */
	if (mainmenu) ctx_popmenu(ctx);

	/* Go through the file */
	for (i=0, j=0; j < size; j++)
	{
		/* Find the end of the line */
		if (addr[j] != '\n') continue;

		/* Copy the line to our tiny buffer */
		memzero(&buf[o], sizeof(buf) - o);
		memcpy(&buf[o], &addr[i], (sizeof(buf)-o) < j-i ? (sizeof(buf)-o) : j-i);

		/* Another line */
		lineno++;

		/* Next line starts here */
		i = j+1;

		for (k=0; k < (strlen(&buf[o])+1); k++)
		{
			/* Skip comment lines in files silently */
			if (buf[o+k] == '#' || buf[o+k] == '\n' || buf[o+k] == '\0')
			{
				buf[o] = '\n';
				break;
			}

			/* When non-whitespace is found, accept it as a valid line */
			if (buf[o+k] != '\t' && buf[o+k] != ' ') break;
		}

		/* Ignore the line when it is empty */
		if (buf[o] == '\n') continue;
	
		ret = ctx_command(ctx, buf);
		ctx_flush(ctx, ret);
		if (ret != 200)
		{
			ctx_printf(ctx, "Code %u occured on line %u of %s\n", ret, lineno, args);
				break;
		}
	}

	munmap(addr, st.st_size);
	close(f);

	return ret;
}

VOID ctx_where(struct sixxsd_context *ctx, char *buf, unsigned int buflen);
VOID ctx_where(struct sixxsd_context *ctx, char *buf, unsigned int buflen)
{
	unsigned int	i, o = 0;
	int		k;

	memzero(buf, buflen);

	k = snprintf(&buf[o], buflen-o, "main");
	if (snprintfok(k, buflen-o))
	{
		o+=k;

		for (i=0,k=0; k == 0 && i < ctx->menu_depth; i++)
		{
			k = snprintf(&buf[o], buflen-o, " > %s", ctx->menu[i]->cmd);
			if (!snprintfok(k, buflen-o)) break;

			o += k;
			k = 0;
		}
	}

	if (k != 0) ctx_printf(ctx, "No buffer space available for determining menu location\n");
}


int ctx_fullhelp(struct sixxsd_context *ctx, struct ctx_menu *menu);
int ctx_fullhelp(struct sixxsd_context *ctx, struct ctx_menu *menu)
{
	int			i = 0, c = 0;
	static const char	fmt[] = "%-14s%-22s%4s %s\n";
	char			buf[1024];

	ctx_where(ctx, buf, sizeof(buf));
	ctx_printdf(ctx, "===============> %s\n", buf);
	ctx_printdf(ctx, fmt, "help", "", "", "Help topics");

	for (i=1; menu[i].cmd; i++)
	{
		/* Skip items without a description */
		if (!menu[i].description) continue;

		/* Should work */
		ctx_printdf(ctx, fmt,
			menu[i].cmd,
			menu[i].options && menu[i].options != CONTEXT_SUB ? menu[i].options : "",
			menu[i].options == CONTEXT_SUB ? "[>>]" : "",
			menu[i].description);
		c++;
	}

	if (c == 0)
	{
		ctx_printf(ctx, "No commands in this menu are available for you\n");
		return 401;
	}

	ctx_printdf(ctx, fmt, "help", "", "", "Help topics");
	ctx_printdf(ctx, "\n");

	for (i=1; menu[i].cmd; i++)
	{
		/* Skip items without a description */
		if (!menu[i].description) continue;

		/* Call all commands that are a submenu */
		if (menu[i].options != CONTEXT_SUB) continue;

		ctx_command(ctx, menu[i].cmd);
		ctx_command(ctx, "fullhelp");
		ctx_command(ctx, "..");
	}

	ctx_printdf(ctx, "<=============== %s\n\n", buf);
	return 200;
}

int ctx_help(struct sixxsd_context *ctx, struct ctx_menu *menu);
int ctx_help(struct sixxsd_context *ctx, struct ctx_menu *menu)
{
	int			i = 0, count = 0;
	static const char	fmt[] = "%-24s%-22s%4s %s\n";

	for (i=1; menu[i].cmd; i++)
	{
		/* Skip items without a description */
		if (!menu[i].description) continue;

		/* Should work */
		ctx_printdf(ctx, fmt,
			menu[i].cmd,
			menu[i].options && menu[i].options != CONTEXT_SUB ? menu[i].options : "",
			menu[i].options == CONTEXT_SUB ? "[>>]" : "",
			menu[i].description);
		count++;
	}

	if (count == 0)
	{
		ctx_printf(ctx, "No commands in this menu are available for you\n");
		return 304;
	}

	ctx_printdf(ctx, fmt, "help", "", "", "Help topics");
	return 200;
}

VOID ctx_popmenu(struct sixxsd_context *ctx)
{
	ctx->menu_depth = 0;
}

/* Evaluate commands */
int ctx_commandmenu(struct sixxsd_context *ctx, const unsigned int argc, const char *args[], struct ctx_menu *menu)
{
	unsigned int	i = 0, j = 0;
	size_t		len = 0;
	char		buf[1024];
	int		k;

	/* Current menu? */
	if (!menu)
	{
		if (ctx->menu_depth > 0) menu = ctx->menu[ctx->menu_depth-1];
		else menu = ctx_menu_main;
		assert(menu);
	}

	/* Are we still in Kansas? */
	if (argc > 0 && strcasecmp(args[0], ".") == 0)
	{
		ctx_where(ctx, buf, sizeof(buf));
		ctx_printf(ctx, "%s\n", buf);
		return 200;
	}

	if (menu == ctx_menu_main)
	{
		/* Nowhere yet */
		ctx->menu_depth = 0;
	}
	else
	{
		/* The enemy gate is down - keep track where we are */
		if (ctx->menu[ctx->menu_depth-1] != menu)
		{
			ctx->menu[ctx->menu_depth] = menu;
			ctx->menu_depth++;
		}
	}

	/* Just select this menu? */
	if (argc == 0 || strlen(args[0]) == 0)
	{
		ctx_where(ctx, buf, sizeof(buf));
		ctx_printf(ctx, ">> %s (use '..' or 'end' to go up one level)\n", buf);
		return 204;
	}

	/* Up? */
	j = 0;
	if (strcasecmp(args[0], "/") == 0)
	{
		ctx_popmenu(ctx);
		j = 1;
	}

	if (	ctx->menu_depth > 0 &&
		(
		strcasecmp(args[0], "..") == 0 ||
		strcasecmp(args[0], "end") == 0
		))
	{
		ctx->menu_depth--;
		j = 1;
	}

	if (j == 1)
	{
		if (argc == 1)
		{
			ctx_where(ctx, buf, sizeof(buf));
			ctx_printf(ctx, "<< %s\n", buf);
			return 204;
		}

		/* Continue one level above, one command less */
		return ctx_commandmenu(ctx, argc-1, &args[1], ctx->menu_depth > 0 ? ctx->menu[ctx->menu_depth-1] : ctx_menu_main);
	}

	/* Always try to give a helping hand */
	if (strcasecmp(args[0], "help"		) == 0) return ctx_help(ctx, menu);
	if (strcasecmp(args[0], "fullhelp"	) == 0) return ctx_fullhelp(ctx, menu);

	/* Go through the menu and find the wanted entry */
	for (j=0; j < 2; j++)
	{
		/* Temporarily switch over to the 'cmd' range and try there */
		if (j == 1) menu = ctx_menu_cmd;

		for (i=1; menu[i].cmd; i++)
		{
			len = strlen(menu[i].cmd);
			if (	(strncasecmp(menu[i].cmd, args[0], len) != 0) ||
				(args[0][len] != ' ' && args[0][len] != '\0')) continue;

			k = argc-1;
			if (	(menu[i].args_min == -1 || menu[i].args_min <= k) &&
				(menu[i].args_max == -1 || menu[i].args_max >= k))
			{
				if (!menu[i].func)
				{
					ctx_printf(ctx, "Function is actually not implemented\n");
					return 500;
				}

				return menu[i].func(ctx, k, &args[1]);
			}

			ctx_printf(ctx, "Command '%s' requires arguments: %s %s (min=%d, max=%d, given=%u)\n", menu[i].cmd, menu[i].cmd,
					menu[i].options == (char *)-1 ? "[submenu, see 'help']" : (menu[i].options ? menu[i].options : ""),
					menu[i].args_min, menu[i].args_max, k);
			return 404;
		}
	}

	ctx_where(ctx, buf, sizeof(buf));
	mdolog(LOG_INFO, "Unknown command: %s >> %s\n",
		buf, args[0]);

	ctx_printf(ctx, "Unknown command: %s >> %s\n", buf, args[0]);
	return 404; 
}

int ctx_commandA(struct sixxsd_context *ctx, const char *command);
int ctx_commandA(struct sixxsd_context *ctx, const char *command)
{
	char		*buffer = NULL, buf[4096];
	const char	*cmd = command;
	int		ret;
	unsigned int	o = 0, j, old_depth = ctx->menu_depth;
	struct ctx_menu	*old_menu[lengthof(ctx->menu)];
	const char	*args[128];

	/* Skip leading white space */
	for (o=0; cmd[o] == ' ' || cmd[o] == '\t'; o++);

	/* Be nice about empty lines */
	if (cmd[o] == '\0')
	{
		ctx_printf(ctx, "Thank you for your empty line\n");
		return 200;
	}

	/* Be nice about comments and just ignore them */
	if (cmd[o] == '#' || (cmd[o] == '/' && cmd[o+1] == '/'))
	{
		ctx_printf(ctx, "I appreciate your comments\n");
		return 200;
	}

	memcpy(old_menu, ctx->menu, sizeof(old_menu));

	/* Copy the full command in our local copy which we can modify */
	if (cmd != buf)
	{
		j = strlen(&cmd[o])+1;
		if (j > sizeof(buf))
		{
			ctx_printf(ctx, "Command too long for processing\n");
			return 500;
		}

		memcpy(buf, &cmd[o], j);
		o = 0;
	}

	/* buf now contains our commands */

	j = parseargs(ctx, buf, args, lengthof(args));

	if (j == 0)
	{
		ctx_printf(ctx, "No command given!?\n");
		return 425;
	}

	ret = ctx_commandmenu(ctx, j, args, NULL);

	/* Free the buffer */
	if (buffer) mfree(buffer, buflen, "command_buffer");
	buffer = NULL;

	/* Sometimes we want it to change menu's */
	if (ret == 204) ret = 200;
	else
	{
		ctx->menu_depth = old_depth;
		memcpy(ctx->menu, old_menu, sizeof(ctx->menu));
	}

	return ret;
}

int ctx_command(struct sixxsd_context *ctx, const char *command)
{
	int ret;

	thread_setnotice(command);
	ret = ctx_commandA(ctx, command);
	thread_setnotice(NULL);

	return ret;
}

