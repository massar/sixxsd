/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2012 All Rights Reserved
***********************************************************/

#include "sixxsd.h"

/* Debugging? */
#ifdef DEBUGALL
#define DD(x) x
#else
#define DD(x) {}
#endif

VOID doelogA(int level, int errnum, const char *module, const char *fmt, va_list ap)
{
	char		buf[16*1024];
	unsigned int	i;
	int		k;

#ifndef DEBUG
	/*
	 * Don't output debug information when we are not verbose enough
	 * or when debugging for that module is disabled.
	 */
	if (	level == LOG_DEBUG && g_conf && (
		g_conf->verbose < 3 || (
		(strcasecmp(module, "sixxsd")	== 0 && !g_conf->verbose_sixxsd) ||
		(strcasecmp(module, "ayiya")	== 0 && !g_conf->verbose_ayiya) ||
		(strcasecmp(module, "common")	== 0 && !g_conf->verbose_common) ||
		(strcasecmp(module, "config")	== 0 && !g_conf->verbose_config) ||
		(strcasecmp(module, "prefix")	== 0 && !g_conf->verbose_prefix) ||
		(strcasecmp(module, "thread")	== 0 && !g_conf->verbose_thread))))
	{
		return;
	}
#endif

	/* Clean out the mess */
	memzero(buf, sizeof(buf));

	/* Format the string */
	k = vsnprintf(buf, sizeof(buf), fmt, ap);
	if (!snprintfok(k, sizeof(buf)))
	{
		snprintf(buf, sizeof(buf), "[Log line way too long: %u/%u bytes]\n", k, (unsigned int)sizeof(buf));
		level = LOG_ERR;
	}

	/* Append errno description? */
	if (errnum != 0)
	{
		i = strlen(buf);
		if (i == 0) i = 1;
		if (i < (sizeof(buf)-10))
		{
			/* Add ": " overwriting the \n which has to be present */
			buf[i-1] = ':';
			buf[i] = ' ';
			buf[i+1] = '\0';

			errno = 0;
			strerror_r(errnum, &buf[i+1], sizeof(buf) - (i+2));

			i = strlen(buf);
			k = snprintf(&buf[i], sizeof(buf)-i, " (errno %d)\n", errnum);
			if (!snprintfok(k, sizeof(buf)-i))
			{
				/* Doesn't hurt when it doesn't fit, just terminate it */
				buf[i] = '\0';
			}
		}
	}

	/* Send it to stdout/stderr if possible */
	if (g_conf && !g_conf->daemonize)
	{
		FILE *out = (level == LOG_DEBUG || level == LOG_ERR ? stderr : stdout);

		time_t			te = gettime();
		struct tm		teem;
		char			buf2[100];
		unsigned long int	t = te;

		localtime_r(&te, &teem);
		strftime(buf2, sizeof(buf2), "%Y-%m-%d_%H:%M:%S", &teem);
		fprintf(out, "%lu %s ", t, buf2);

		if (g_conf && g_conf->verbose)
		{
			fprintf(out,
				"%s %s: ",
				level == LOG_DEBUG ?	"debug" :
				(level == LOG_ERR ?	"error" :
				(level == LOG_WARNING ?	"warn" :
				(level == LOG_NOTICE ?	"notice" :
				(level == LOG_INFO ?	"info" : "(!?)")))),
				module);
		}
		else if (level == LOG_ERR) fprintf(out, "Error: ");

		fprintf(out, "%s", buf);
	}
	/* Send it to syslog otherwise */
	else
	{
		if (g_conf && !g_conf->opened_syslog)
		{
			openlog("sixxsd", 0, LOG_DAEMON);
			g_conf->opened_syslog = true;
		}
#ifdef DEBUG
		/*
  		 * Avoid sending to syslog when in debug mode,
  		 * causing syslog socket to be opened etc
  		 */
		if (g_conf)
		{
#endif
		syslog(LOG_LOCAL7|level, "%s", buf);
#ifdef DEBUG
		}
		else
		{
			fprintf(level == LOG_DEBUG || level == LOG_ERR ? stderr : stdout, "%s", buf);
		}
#endif
	}
}

SOCKET use_uri_ctx(struct sixxsd_context *ctx, BOOL doconnect, const char *uri, const char *defaultservice, struct socketpool *pool, uint32_t tag)
{
	char	buf[2048];
	SOCKET	r;

	memzero(buf, sizeof(buf));
	r = use_uri(buf, sizeof(buf), doconnect, uri, defaultservice, pool, tag);
	if (strlen(buf) > 0) ctx_printf(ctx, "%s", buf);

	return r;
}

int writefile(struct sixxsd_context *ctx, const char *filename, struct pl_rule *rules, PTR *data)
{
	FILE		*f;
	char		buf[1024];
	unsigned int	r;
	PTR		*store, *s = NULL;
	int		ret = 200;

	f = fopen(filename, "w+");
	if (!f)
	{
		ctx_printef(ctx, errno, "Couldn't open user file %s\n", filename);
		return 404;
	}

	/* Make the read/write only by us */
	fchmod(fileno(f), 0600);

	/* Walk through all the rules */
	for (r = 0; rules[r].type != PLRT_END; r++)
	{
		store = (PTR *)(((char *)data) + rules[r].offset);

		switch (rules[r].type)
		{
			case PLRT_STR2048:
			case PLRT_STR512:
			case PLRT_STR256:
			case PLRT_STR128:
			case PLRT_STRING:
				/* No string defined? Then skip it */
				if (!(*((char **)store))) continue;

				s = store;
				break;

			case PLRT_UINT32:
				snprintf(buf, sizeof(buf), "%u", *((uint32_t *)store));
				s = (PTR *)buf;
				break;

			case PLRT_UINT64:
				snprintf(buf, sizeof(buf), "%" PRIu64, *((uint64_t *)store));
				s = (PTR *)buf;
				break;

			case PLRT_BOOL:
				snprintf(buf, sizeof(buf), "%s", yesno(*((BOOL *)store)));
				s = (PTR *)buf;
				break;

			case PLRT_IP:
				inet_ntopA((const IPADDRESS *)store, buf, sizeof(buf));
				s = (PTR *)buf;
				break;

			case PLRT_END:
			default:
				ctx_printf(ctx, "Unknown parseline type %u for option %s\n", rules[r].type, rules[r].title);
				ret = 400;
				break;
		}

		assert(s);
		if (!s)
		{
			ctx_printf(ctx, "Missing variable\n");
			ret = 500;
			break;
		}

		fprintf(f, "%s \"%s\"\n", rules[r].title, (char *)s);
	}

	/* Close the file */
	fclose(f);

	if (ret == 200) ctx_printf(ctx, "File written succesfully\n");

	return ret;
}

int parseline(struct sixxsd_context *ctx, char *line, const char *split, struct pl_rule *rules, PTR *data)
{
	unsigned int	r, l;
	char		*end = NULL, *val = NULL, *p = NULL;
	PTR		*store;

	/* Chop off \n and \r and white space */
	p = &line[strlen(line)-1];
	while (	p >= line && (
		*p == '\n' ||
		*p == '\r' ||
		*p == '\t' ||
		*p == ' ')) *p-- = '\0';

	/* Ignore comments and emtpy lines */
	if (	strlen(line) == 0 ||
		line[0] == '#' ||
		line[0] == ';' ||
		(line[0] == '/' && line[1] == '/'))
	{
		ctx_printf(ctx, "Ignoring comment line\n");
		return 200;
	}

	/* Get the end of the first argument */
	p = line;
	end = &line[strlen(line)-1];

	/* Skip until whitespace */
	while ( p < end && strncasecmp(p, split, strlen(split)) != 0) p++;

	/* Terminate this argument */
	if (p != end) *p = '\0';
	p++;

	/* Skip whitespace */
	while (	p < end &&
		*p == ' ' &&
		*p == '\t') p++;

	/* Start of the value */
	val = p+(strlen(split)-1);

	/* If starting with quotes, skip until next quote */
	if (*p == '"' || *p == '\'')
	{
		p++;

		/* Find next quote */
		while (	p <= end &&
			*p != *val &&
			*p != '\0') p++;

		/* Terminate */
		*p = '\0';
		/* Skip the first quote */
		val++;
	}

	/* Otherwise it is already terminated above */

	/* Walk through all the rules */
	for (r = 0; rules[r].type != PLRT_END; r++)
	{
		if (strcasecmp(line, rules[r].title) != 0) continue;

		store = (PTR *)(((char *)data) + rules[r].offset);
		l = 0;

		switch (rules[r].type)
		{
			case PLRT_STRING:
				if (*((char **)store)) free(*((char **)store));
				*((char **)store) = mstrdup(val);
				break;

			case PLRT_STR2048:
				l += (512 + 1024);
			case PLRT_STR512:
				l += 256;
			case PLRT_STR256:
				l += 128;
			case PLRT_STR128:
				l += 128;
				/* Length is implicit because of the type */
				strncpy((char *)store, val, l);
				break;

			case PLRT_UINT32:
				if (sscanf(val, "%u", ((uint32_t *)store)) == 1) break;

				ctx_printf(ctx, "'%s' is not a valid uint32_t\n", val);
				return 400;

			case PLRT_UINT64:
				if (sscanf(val, "%" PRIu64, ((uint64_t *)store)) == 1) break;

				ctx_printf(ctx, "'%s' is not a valid uint64_t\n", val);
				return 400;

			case PLRT_BOOL:
				*((BOOL *)store) = isyes(val);
				break;

			case PLRT_IP:
				inet_ptonA(val, (IPADDRESS *)store, NULL);
				break;

			case PLRT_END:
			default:
				ctx_printf(ctx, "Unknown parseline type %u for option %s\n", rules[r].type, rules[r].title);
				return 400;
		}

		return 200;
	}

	ctx_printf(ctx, "No matching rule found\n");
	return 404;
}

int parseargs(struct sixxsd_context *ctx, char *buf, const char *args[], unsigned int maxargc)
{
	unsigned int	o, s, argc;
	BOOL		quoted = false;

	for (s = o = argc = 0; buf[o] != '\0' ;o++)
	{
		if (buf[o] == '"')
		{
			/* Don't want to see this quote in the output */
			buf[o] = '\0';

			/* Swap quoted mode */
			quoted = !quoted;

			/* Start -> put a ref in place */
			if (quoted)
			{
				s = o+1;
				args[argc++] = &buf[o+1];
				if (argc >= maxargc)
				{
					ctx_printf(ctx, "Too many arguments (max %u)\n", maxargc);
					break;
				}
			}

			continue;
		}

		/* Escape? */
		if (buf[o] == '\\')
		{
			/* Shove it all over, removing the escape char */
			memmove(&buf[o], &buf[o+1], strlen(&buf[o+1])+1);

			/* Process the escaped char if we know it */

			switch(buf[o])
			{
			case 'a':	buf[o] = '\a';		break;
			case 'b':	buf[o] = '\b';		break;
			case 'f':	buf[o] = '\f';		break;
			case 'n':	buf[o] = '\n';		break;
			case 'r':	buf[o] = '\r';		break;
			case 't':	buf[o] = '\t';		break;
			case 'v':	buf[o] = '\v';		break;

			default:
				/* Just keep the char and don't modify it */
				break;
			}

			/*
			 * Note that we processed 2 chars, but as we moved it,
  			 * we are skipping 2 with the above for o++
  			 */
			continue;
		}

		/* Quoted so don't look in here */
		if (quoted) continue;

		/* Are we at the beginning? Get our first argument */
		if (s == o)
		{
			args[argc++] = &buf[o];
			if (argc >= maxargc) break;
		}

		/* Non-Whitespace? -> Next char */
		if (buf[o] != ' ' && buf[o] != '\t') continue;

		/* Find start of next field */
		while (buf[o] == ' ' || buf[o] == '\t') buf[o++] = '\0';

		/* Our current 'start' */
		s = o;

		/* Two steps forward, one step back (because of the o++ in the for loop) */
		o--;
	}

	return argc;
}

