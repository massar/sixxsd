/*************************************************************
 SixXS PoP Statistics Collector Daemon
 by Jeroen Massar <jeroen@sixxs.net>
**************************************************************
 Formerly trafficpopd, but now will also handle latency
 for all v4+ PoPs

 Filestructure after v4 conversion under /home/sixxs/rrd/:
  <popname>/
	traffic/
		T<tid>.rrd
	latency/
		T<tid>.rrd
		P<popname>.rrd
*************************************************************/

/* Request data every x minutes */
#define EVERY 15

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <syslog.h>
#include <inttypes.h>
#include <mysql/mysql.h>
#include <mysql/errmsg.h>
#include <sys/stat.h>
#include <dirent.h>
#include <assert.h>

#include "common.h"

#ifndef ATTR_FORMAT
#if defined(__GNUC__)
#define ATTR_RESTRICT __restrict
#define ATTR_FORMAT(type, x, y) __attribute__ ((format(type, x, y)))
#else
#define ATTR_FORMAT(type, x, y) /* nothing */
#endif
#endif

/* Should be long enough for most things ;) */
#define _MAX_PATH 1024

#include <rrd.h>

const char g_rrdpath[] = "/home/sixxs/rrd";			/* The path to the RRD's (usually /home/sixxs/rrd) no trailing '/' */

const char g_cfgfile[] = "/sixxs/etc/config.inc";		/* Configuration file */

#define		BUFFER_SIZE	(100*1024)			/* 100kb Buffer					*/
const char	*g_pop_service	= "42003";			/* The service port number			*/
bool		g_debug		= false;			/* Don't output debug output per default	*/
unsigned int	g_rrd_errcnt;					/* RRD error count				*/
char		*g_db_server	= NULL,				/* Database details */
		*g_db_name	= NULL,
		*g_db_user	= NULL,
		*g_db_pass	= NULL,
		*g_pop_name	= NULL,				/* Currently active PoP */
		*g_pop_mgmt	= NULL,				/* "" mgmt interface */
		*g_pop_version	= NULL;				/* "" version */

/**************************************
  Functions
**************************************/
void mdologA(int level, const char *fmt, va_list ap) ATTR_FORMAT(printf, 2, 0);
void mdologA(int level, const char *fmt, va_list ap)
{
	FILE	*f;

	/* No debug output when we don't want it */
/*	if (!g_debug && level == LOG_DEBUG) return; */

	/* Log to our beloved php.err as that is the one we actually check ;) */
	f = fopen("/var/log/php.err", "a");
	if (f)
	{
		vfprintf(f, fmt, ap);
		fclose(f);
	}
	else
	{
		/* If we could not log to the file, log to syslog */
		vsyslog(LOG_LOCAL7|level, fmt, ap);
	}
}

void mdolog(int level, const char *fmt, ...) ATTR_FORMAT(printf, 2, 3);
void mdolog(int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	mdologA(level, fmt, ap);
	va_end(ap);
}

VOID doelogA(int level, int UNUSED errnum, const char UNUSED *module, const char *fmt, va_list ap)
{
	mdologA(level, fmt, ap);
}

MYSQL *db_connect(void);
MYSQL *db_connect(void)
{
	MYSQL *db;

	db = mysql_init(NULL);
	if (!db)
	{
		mdolog(LOG_ERR, "Couldn't initialize MySQL\n");
		return NULL;
	}

	if (!mysql_real_connect(db, g_db_server, g_db_user, g_db_pass, g_db_name, 0, NULL, 0))
	{
		mdolog(LOG_ERR, "Couldn't open database: %s\n", mysql_error(db));
		return NULL;
	}

	return db;
}

void db_disconnect(MYSQL **db);
void db_disconnect(MYSQL **db)
{
	assert(db);
	if (!*db) return;
	mysql_close(*db);
	*db = NULL;
}

void db_suckrows(MYSQL_RES *res);
void db_suckrows(MYSQL_RES *res)
{
	if (res)
	{
		while (mysql_fetch_row(res));
		mysql_free_result(res);
	}
}

bool db_query(MYSQL **db, const char *q);
bool db_query(MYSQL **db, const char *q)
{
	unsigned int try, max_tries = 3, e;

	for (try = 0; try < max_tries; try++)
	{
		if (!*db) *db = db_connect();
		if (!*db) break;

		if (mysql_query(*db, q) == 0) return true;

		e = mysql_errno(*db);

		/* Don't complain when it is the first try */
		if (!(e == CR_SERVER_GONE_ERROR && try == 0))
		{
			mdolog(LOG_ERR, "SQL error: %s : %s [%u/%u/%u]\n", mysql_error(*db), q, e, try+1, max_tries);
		}

		/* Cleanup and restart a connection later */
		db_disconnect(db);

		/* Error cases we consider that we should retry */
		if (	e == CR_SERVER_GONE_ERROR ||
			e == CR_SERVER_LOST ||
			e == CR_SERVER_LOST_EXTENDED
			)
		{
			/* Another try */
			continue;
		}

		/* Give up */
		break;
	}

	return false;
}

bool db_readconfig(void);
bool db_readconfig(void)
{
	FILE		*f;
	char		line[1024];
	unsigned int	l, v, i, s, lineno = 0;
	bool		ret = true;
	struct
	{
		const char	*name;
		char		**var;
	} vars[] =
	{
		{ "db_server",	&g_db_server },
		{ "db_name",	&g_db_name },
		{ "db_user",	&g_db_user },
		{ "db_pass",	&g_db_pass },
	};

	f = fopen(g_cfgfile, "r");
	if (!f)
	{
		mdolog(LOG_ERR, "Could not read configuration file %s: %d %s\n", g_cfgfile, errno, strerror(errno));
		return false;
	}

	while (fgets(line, sizeof(line), f) == line)
	{
		/* Another line */
		lineno++;

		/* Length of the line */
		l = strlen(line);

		/* Skip empty lines */
		if (l == 0) continue;

		if (l > 0 && line[l-1] == '\n')
		{
			line[l-1] = '\0';
			l--;
		}

		/* Skip whitespace */
		for (i=0; i < l && (line[i] == ' ' || line[i] == '\t'); i++);

		/* We only care about variables */
		if (i >= l || line[i] != '$') continue;
		i++;

		/* Start of this var */
		s = i;

		/* Skip chars till whitespace */
		for (; i < l && line[i] != ' ' && line[i] != '\t'; i++);

		/* EOL? */
		if (i >= l) continue;

		/* Terminate the variable name */
		line[i] = '\0';

		/* Do we know it? */
		for (v = 0; v < lengthof(vars); v++)
		{
			if (strcasecmp(vars[v].name, &line[s]) == 0) break;
		}

		/* Unknown variable name */
		if (v >= lengthof(vars)) continue;

		if (*vars[v].var)
		{
			mdolog(LOG_ERR, "Variable %s on line %u re-appeared another time?\n", vars[v].name, lineno);
			ret = false;
			break;
		}

		/* Skip white space */
		for (i++; i < l && (line[i] == ' ' || line[i] == '\t'); i++);

		/* EOL? */
		if (i >= l) continue;

		/* Assignment? */
		if (line[i] != '=')
		{
			mdolog(LOG_ERR, "Strange configuration file on line %u, position %u (%c) missing assignment operator\n", lineno, i, line[i]);
			ret = false;
			break;
		}

		/* Skip white space */
		for (i++ ; i < l && (line[i] == ' ' || line[i] == '\t'); i++);

		/* EOL? */
		if (i >= l) continue;

		/* Start quote? */
		if (line[i] != '"')
		{
			mdolog(LOG_ERR, "Strange configuration file on line %u, position %u (%c) missing start quote\n", lineno, i, line[i]);
			ret = false;
			break;
		}

		/* Got the variable */
		i++;
		s = i;

		/* Find the end */
		for (; i < l && line[i] != '"'; i++);

		/* EOL? */
		if (i >= l) continue;

		/* No end quote? */
		if (line[i] != '"')
		{
			mdolog(LOG_ERR, "Strange configuration file on line %u, position %u (%c) missing end quote\n", lineno, i, line[i]);
			ret = false;
			break;
		}

		/* Terminate it */
		line[i] = '\0';

		/* Copy it */
		*vars[v].var = strdup(&line[s]);
	}

	fclose(f);

	if (ret)
	{
		for (v = 0; v < lengthof(vars); v++)
		{
			if (!*vars[v].var)
			{
				mdolog(LOG_ERR, "Variable %s is unconfigured\n", vars[v].name);
				ret = false;
			}
		}
	}


	return ret;
}

void create_dirs(void);
void create_dirs(void)
{
	char		filename[_MAX_PATH];
	const char	*types[] = { "traffic", "latency" };
	unsigned int	i;
	int		r;
	struct stat	stats;

	/* Check for and otherwise create the PoP dir */
	r = snprintf(filename, sizeof(filename), "%s/%s", g_rrdpath, g_pop_name);
	if (!snprintfok(r, sizeof(filename)))
	{
		mdolog(LOG_DEBUG, "[%s] Could not construct dirname, too long\n", g_pop_name);
		return;
	}

	if (stat(filename, &stats) != 0)
	{
		mdolog(LOG_DEBUG, "[%s] Dir not found, creating dir '%s'...\n", g_pop_name, filename);
		/* Create the directory */
		mkdir(filename, 0755);
	}

	for (i = 0; i < lengthof(types); i++)
	{
		/* Check for and otherwise create the stats dir */
		r = snprintf(filename, sizeof(filename), "%s/%s/%s", g_rrdpath, g_pop_name, types[i]);
		if (!snprintfok(r, sizeof(filename)))
		{
			mdolog(LOG_DEBUG, "[%s] Could not construct stats dirname, too long\n", g_pop_name);
			return;
		}

		if (stat(filename, &stats) != 0)
		{
			mdolog(LOG_DEBUG, "[%s] Dir not found, creating dir '%s'...\n", g_pop_name, filename);
			mkdir(filename, 0755);
		}
	}
}

void disconnect_client(int *sockfd);
void disconnect_client(int *sockfd)
{
	if (*sockfd == -1) return;
	
	close(*sockfd);
	*sockfd = -1;
}

/* Interface is sixxs<x> for v3, but T<x> for v4 and up */
void create_rrd(const char *type, const char *iface);
void create_rrd(const char *type, const char *iface)
{
	char		filename[_MAX_PATH];
	int		r;
	const char	*args_traffic[] =
	{
		"create",
		NULL,
		"-s",
		"1800",
		"DS:inoct:COUNTER:3600:0:U",
		"DS:inpkt:COUNTER:3600:0:U",
		"DS:outoct:COUNTER:3600:0:U",
		"DS:outpkt:COUNTER:3600:0:U",
		"RRA:MIN:0.5:1:600",
		"RRA:MIN:0.5:6:700", 
		"RRA:MIN:0.5:24:775",
		"RRA:MIN:0.5:288:797",
		"RRA:AVERAGE:0.5:1:600",
		"RRA:AVERAGE:0.5:6:700",
		"RRA:AVERAGE:0.5:24:775",
		"RRA:AVERAGE:0.5:288:797",
		"RRA:MAX:0.5:1:600",
		"RRA:MAX:0.5:6:700",
		"RRA:MAX:0.5:24:775",
		"RRA:MAX:0.5:288:797",
       		NULL
	};

	const char *args_latency[] =
	{
		"create",
		NULL,
		"-s",
		"3600",
		"DS:latency:GAUGE:7200:0:U",
		"DS:loss:GAUGE:7200:0:U",
		"RRA:MIN:0.5:1:600",
		"RRA:MIN:0.5:6:700",
		"RRA:MIN:0.5:24:775",
		"RRA:MIN:0.5:288:797",
		"RRA:AVERAGE:0.5:1:600",
		"RRA:AVERAGE:0.5:6:700",
		"RRA:AVERAGE:0.5:24:775",
		"RRA:AVERAGE:0.5:288:797",
		"RRA:MAX:0.5:1:600",
		"RRA:MAX:0.5:6:700",
		"RRA:MAX:0.5:24:775",
		"RRA:MAX:0.5:288:797",
		NULL
	};

	/* Make sure the dirs are there */
	create_dirs();

	r = snprintf(filename, sizeof(filename), "%s/%s/%s/%s.rrd", g_rrdpath, g_pop_name, type, iface);
	if (!snprintfok(r, sizeof(filename)))
	{
		mdolog(LOG_DEBUG, "[%s] Could not construct RRD filename, too long\n", g_pop_name);
		return;
	}

	mdolog(LOG_DEBUG, "[%s] Creating %s\n", g_pop_name, filename);

	rrd_clear_error();

	if (strcasecmp(type, "traffic") == 0)
	{
		/* The filename */
		args_traffic[1] = filename;

		/* v4 uses gauges instead of counters */
		/* When fetched we reset them */
		if (strcasecmp(g_pop_version, "v4") == 0)
		{
			args_traffic[4] = "DS:inoct:ABSOLUTE:3600:0:U";
			args_traffic[5] = "DS:inpkt:ABSOLUTE:3600:0:U";
			args_traffic[6] = "DS:outoct:ABSOLUTE:3600:0:U";
			args_traffic[7] = "DS:outpkt:ABSOLUTE:3600:0:U";
		}

		rrd_create(lengthof(args_traffic) - 1, (char **)args_traffic);
	}
	else
	{
		/* The filename */
		args_latency[1] = filename;

		rrd_create(lengthof(args_latency) - 1, (char **)args_latency);
	}


	if (rrd_test_error())
	{
		mdolog(LOG_ERR, "[%s] RRD Creation error: %s\n", g_pop_name, rrd_get_error());

		/* We only log errors, but don't fail */
		/* exit(-1); */
	}
}

void update_interface(const char *type, const char *iface, const char *values);
void update_interface(const char *type, const char *iface, const char *values)
{
	char		filename[_MAX_PATH];
	const char	*args[4];
	struct stat	stats;
	unsigned int	j;
	int		r;

	args[0] = "update";
	args[1] = filename;
	args[2] = values;
	args[3] = NULL;

	r = snprintf(filename, sizeof(filename), "%s/%s/%s/%s.rrd", g_rrdpath, g_pop_name, type, iface);
	if (!snprintfok(r, sizeof(filename)))
	{
		mdolog(LOG_DEBUG, "[%s] Could not construct Interface RRD filename, too long\n", g_pop_name);
		return;
	}

#ifdef DEBUG
	if (1)
	{
		mdolog(LOG_DEBUG, "Update %s %s %s %s", g_pop_name, type, iface, values);
		return;
	}
#endif

	/* Does the RRD exist? */
	if (stat(filename, &stats) != 0) create_rrd(type, iface);

	mdolog(LOG_DEBUG, "[%s] Updating RRD %s with %s\n", g_pop_name, filename, values);

	rrd_clear_error();

	/* Stolen from DAPd: */
	/* "kludge" to fix the "API" for rrdtool */
	optind = 0;
	opterr = 0;

	rrd_update((sizeof(args)/sizeof(char *))-1, (char **)&args[0]);
	if (!rrd_test_error()) return;

	/* Show only 3 RRD errors per PoP, otherwise it would get too noisy */
	if (g_rrd_errcnt < 3)
	{
		/* Log and try again */
		mdolog(LOG_ERR, "[%s] RRD Update error %u: %s\n", g_pop_name, g_rrd_errcnt, rrd_get_error());
		for (j=0; j < (sizeof(args)/sizeof(args[0])); j++)
		{
			mdolog(LOG_ERR, "  arg[%u]: \"%s\"\n", j, args[j]);
		}

		g_rrd_errcnt++;
	}
}

void update_interface_traffic(char *iface, uint64_t inoct, uint64_t outoct, uint64_t inpkt, uint64_t outpkt);
void update_interface_traffic(char *iface, uint64_t inoct, uint64_t outoct, uint64_t inpkt, uint64_t outpkt)
{
	char	values[_MAX_PATH];
	int	r;

	/* No numbers, then we don't have to bother logging it */
	if (inoct == 0 && outoct == 0 && inpkt == 0 && outpkt == 0) return;

	r = snprintf(values, sizeof(values), "N:%" PRIu64 ":%" PRIu64 ":%" PRIu64 ":%" PRIu64, inoct, inpkt, outoct, outpkt);
	if (!snprintfok(r, sizeof(values)))
	{
		mdolog(LOG_DEBUG, "[%s] Could not construct Interface Traffic, too long\n", g_pop_name);
		return;
	}

	update_interface("traffic", iface, values);
}

void update_tunnel_latency(char *iface, float loss, float min, float avg, float max, MYSQL **db_);
void update_tunnel_latency(char *iface, float loss, float min, float avg, float max, MYSQL **db_)
{
	unsigned int	tid, j;
	char		q[256];
	MYSQL		*db;
	MYSQL_RES	*res;
	MYSQL_ROW	row;
	double		oldmin, oldmax, oldavg, oldlos;
	bool		ret;
	char		values[_MAX_PATH];
	int		r;

	/* Get the tunnel_id which is passed in as T<xxx> */
	tid = atoi(&iface[1]);

	/* Get the current min/max */
	r = snprintf(q, sizeof(q),
		"SELECT tunnel_latency_min, "
		"tunnel_latency_max, "
		"tunnel_latency_avg, "
		"tunnel_latency_loss "
		"FROM tunnels "
		"WHERE tunnel_id = %u", tid);
	if (!snprintfok(r, sizeof(q)))
	{
		mdolog(LOG_DEBUG, "[%s] Could not construct Latency Query, too long\n", g_pop_name);
		return;
	}

	if (!db_query(db_, q))
	{
		mdolog(LOG_WARNING, "[%s] Tunnel ID %u not found\n", g_pop_name, tid);
		return;
	}

	db = *db_;

	res = mysql_store_result(db);
	j = mysql_num_rows(res);
	row = mysql_fetch_row(res);
	if (row == NULL || j != 1)
	{
		mdolog(LOG_WARNING, "[%s] Could not fetch old stats for %s (%u rows)\n", g_pop_name, iface, j);
		db_suckrows(res);
		return;
	}

	oldmin = atof(row[0]);
	oldmax = atof(row[1]);
	oldavg = atof(row[2]);
	oldlos = atof(row[3]);

	db_suckrows(res);

	if (oldmin == min &&
	    oldmax == max &&
	    oldavg == avg &&
	    oldlos == loss)
	{
		/*
		 * All the same, don't update
		 *
		 * Does mean that lastalive does not get updated either
		 * but there will be a miniscule latency difference
		 * thus actually active tunnels will always be updated.
		 *
		 * This primarily avoids updating tunnels
		 * that do not have any new latency.
		 *
		 * Note that we thus do not update latency RRDs
		 * for tunnels that are not active either which
		 * in all saves quite some overhead.
		 */
		return;
	}

	if (min > oldmin) min = oldmin;
	if (max < oldmax) max = oldmax;

	snprintf(q, sizeof(q),
		"UPDATE tunnels SET "
		"tunnel_latency_loss = %f, "
		"tunnel_latency_min = %f, "
		"tunnel_latency_avg = %f, "
		"tunnel_latency_max = %f",
		loss, min, avg, max);

	if (loss < 100)
	{
		j = strlen(q);
		snprintf(&q[j], sizeof(q)-j, ", tunnel_lastalive = now()");
	}

	j = strlen(q);
	snprintf(&q[j], sizeof(q)-j, " WHERE tunnel_id = %u", tid);

	mdolog(LOG_DEBUG, "[%s] %s\n", g_pop_name, q);

	ret = db_query(db_, q);
	db = *db_;

	if (!ret)
	{
		mdolog(LOG_WARNING, "[%s] Could not update T%u stats\n", g_pop_name, tid);
		return;
	}

	res = mysql_use_result(db);
	db_suckrows(res);

	/* Please also update RRD */
	r = snprintf(values, sizeof(values), "N:%2.2f:%2.2f", avg, loss);
	if (!snprintfok(r, sizeof(values)))
	{
		mdolog(LOG_DEBUG, "[%s] Could not construct Interface Latency, too long\n", g_pop_name);
		return;
	}

	update_interface("latency", iface, values);
}

/* Works for v2 + v3 */
void collectstats3(int sockfd);
void collectstats3(int sockfd)
{
	char		rbuf[BUFFER_SIZE], line[BUFFER_SIZE];
	char		iface[BUFFER_SIZE];
	uint64_t	filled = 0, inoct, outoct, inpkt, outpkt;
	const char	cmd[] = "getstat\r\n";

	/* Read a line from the socket */
	if (sock_getline(sockfd, rbuf, sizeof(rbuf), &filled, line, sizeof(line)) == -1)
	{
		mdolog(LOG_WARNING, "[%s] Didn't receive initial welcome line\n", g_pop_name);
		return;
	}

	/* 'Analyze' the welcome line */
	if (strncmp(line, "+OK ", 4) != 0)
	{
		mdolog(LOG_WARNING, "[%s] Initial response \"%s\" is not +OK\n", g_pop_name, line);
		return;
	}

	mdolog(LOG_DEBUG, "[%s] Received initial line, sending command \"%s\"\n", g_pop_name, cmd);

	/* Send the command */
	if (write(sockfd, cmd, sizeof(cmd)) <= 0)
	{
		mdolog(LOG_WARNING, "[%s] Write returned 0\n", g_pop_name);
		return;
	}

	if (sock_getline(sockfd, rbuf, sizeof(rbuf), &filled, line, sizeof(line)) == -1)
	{
		mdolog(LOG_WARNING, "[%s] \"%s\" resulted in an error\n", g_pop_name, cmd);
		return;
	}

	/* Analyze the answer */
	if (strncmp(line, "+OK ", 4) != 0)
	{
		mdolog(LOG_WARNING, "[%s] \"%s\" resulted in \"%s\"\n", g_pop_name, cmd, line);
		return;
	}

	/* parse the responses */
	while (sock_getline(sockfd, rbuf, sizeof(rbuf), &filled, line, sizeof(line)) != -1)
	{
		/* Was this the end of the list? */
		if (strncmp(line, "+OK ", 4) == 0) break;

		mdolog(LOG_DEBUG, "[%s] received \"%s\"\n", g_pop_name, line);

		sscanf(line, "%s %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64, iface, &inoct, &outoct, &inpkt, &outpkt);

		update_interface_traffic(iface, inoct, outoct, inpkt, outpkt);
	}

	/* End of stats found */
	mdolog(LOG_DEBUG, "[%s] End of stats found\n", g_pop_name);
}

void collectstats4(int sockfd, MYSQL **db);
void collectstats4(int sockfd, MYSQL **db)
{
	char		rbuf[BUFFER_SIZE], line[BUFFER_SIZE];
	char		iface[BUFFER_SIZE];
	uint64_t	filled = 0, inoct, outoct, inpkt, outpkt;
	unsigned int	num_sent, num_recv;
	float		loss, min, avg, max;
	unsigned int	nl;
#ifndef DEBUG
	const char	cmd[] = "tunnel stats RESET\r\n";
#else
	const char	cmd[] = "tunnel stats\r\n";
#endif

	/* Read a line from the socket */
	if (sock_getline(sockfd, rbuf, sizeof(rbuf), &filled, line, sizeof(line)) == -1)
	{
		mdolog(LOG_WARNING, "[%s] Didn't receive initial welcome line\n", g_pop_name);
		return;
	}

	/* 'Analyze' the welcome line */
	if (strncmp(line, "200 ", 4) != 0)
	{
		mdolog(LOG_WARNING, "[%s] Initial response \"%s\" does not start with 200\n", g_pop_name, line);
		return;
	}

	mdolog(LOG_DEBUG, "[%s] Received initial line, sending command \"%s\"\n", g_pop_name, cmd);

	/* Send the command */
	if (write(sockfd, cmd, sizeof(cmd)) <= 0)
	{
		mdolog(LOG_WARNING, "[%s] Write returned 0\n", g_pop_name);
		return;
	}

	if (sock_getline(sockfd, rbuf, sizeof(rbuf), &filled, line, sizeof(line)) == -1)
	{
		mdolog(LOG_WARNING, "[%s] \"%s\" resulted in an error\n", g_pop_name, cmd);
		return;
	}

	/* Analyze the answer */
	if (strncmp(line, "201 ", 4) != 0)
	{
		mdolog(LOG_WARNING, "[%s] \"%s\" resulted in \"%s\"\n", g_pop_name, cmd, line);
		return;
	}

	if (sscanf(&line[4], "%u", &nl) != 1)
	{
		mdolog(LOG_WARNING, "[%s] \"%s\" resulted in \"%s\" which has an invalid line count\n", g_pop_name, cmd, line);
		return;
	}

	while (nl > 0)
	{
		/* parse the responses */
		if (sock_getline(sockfd, rbuf, sizeof(rbuf), &filled, line, sizeof(line)) == -1)
		{
			mdolog(LOG_WARNING, "[%s] Could not get response line for %s\n", g_pop_name, cmd);
			return;
		}

		mdolog(LOG_DEBUG, "[%s] received \"%s\"\n", g_pop_name, line);

		/* Tunnel statistic? */
		if (line[0] == 'T')
		{
			if (sscanf(line, "%s %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " "
					"%u %u %f %f %f %f",
					iface, &inoct, &outoct, &inpkt, &outpkt,
					&num_sent, &num_recv, &loss, &min, &avg, &max) != 11)
			{
				mdolog(LOG_WARNING, "[%s] \"%s\" resulted in \"%s\" which is a broken tunnel result line...\n", g_pop_name, cmd, line);
				return;
			}
		}
		else
		{
			if (sscanf(line, "%s %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64,
					iface, &inoct, &outoct, &inpkt, &outpkt) != 5)
			{
				mdolog(LOG_WARNING, "[%s] \"%s\" resulted in \"%s\" which is a broken uplink/total result line...\n", g_pop_name, cmd, line);
				return;
			}
		}

		/* Update the stats */
		update_interface_traffic(iface, inoct, outoct, inpkt, outpkt);

		/* Only tunnels have latency */
		if (line[0] == 'T')
		{
			/* Update SQL */
			update_tunnel_latency(iface, loss, min, avg, max, db);
		}

		/* Another line read */
		nl--;
	}

	if (sock_getline(sockfd, rbuf, sizeof(rbuf), &filled, line, sizeof(line)) == -1)
	{
		mdolog(LOG_WARNING, "[%s] \"%s\" Failed to read final line\n", g_pop_name, cmd);
	}

	/* Analyze the answer */
	if (strncmp(line, "200 ", 4) != 0)
	{
		mdolog(LOG_WARNING, "[%s] \"%s\" resulted in \"%s\" (wrong end of section)\n", g_pop_name, cmd, line);
		return;
	}

	/* End of stats found */
	mdolog(LOG_DEBUG, "[%s] End of stats found\n", g_pop_name);
}

/* returns: true = ready for traffic, false = still converting */
bool checkv4rrd(void);
bool checkv4rrd(void)
{
	char		scriptname[_MAX_PATH], tmp[_MAX_PATH], tmp2[_MAX_PATH], q[256];
	const char	*dss[] = { "inoct", "inpkt", "outoct", "outpkt" };
	struct stat	stats;
	DIR		*dirp;
	struct dirent	*dp;
	unsigned int	i, j, d, tid, tseq, converts = 0;
	int		r;
	FILE		*f;
	MYSQL		*db = NULL;
	MYSQL_RES	*res;
	MYSQL_ROW	row;

	if (strcasecmp(g_pop_version, "v4") != 0) return true;

	create_dirs();

	/* Did we finish the conversion? */
	snprintf(scriptname, sizeof(scriptname), "%s/%s/traffic/.rrdmode_v4", g_rrdpath, g_pop_name);
	if (stat(scriptname, &stats) == 0) return true;

	/* Did we start the conversion? */
	snprintf(scriptname, sizeof(scriptname), "%s/%s/traffic/.rrdmode_v4.sh", g_rrdpath, g_pop_name);
	if (stat(scriptname, &stats) == 0) return false;

	/* Make sure that the old dir actualyl exists */
	snprintf(tmp, sizeof(tmp), "%s/%s/traffic/", g_rrdpath, g_pop_name);
	if ((dirp = opendir(tmp)) == NULL)
	{
		mdolog(LOG_ERR, "[%s] Could not open directory %s\n", g_pop_name, tmp);
		return false;
	}

	/* Write a shell script which does the conversion here */
	f = fopen(scriptname, "w");
	if (!f)
	{
		mdolog(LOG_ERR, "[%s] Could not create shell script (%s) for conversion of RRDs to v4\n", g_pop_name, scriptname);
		return false;
	}

	/* We'll put some bash in here */
	fprintf(f, "#!/bin/bash\n");

	/* When it executes, log the start time */
	fprintf(f, "echo -n 'RRD to v4 conversion of %s started at ' && date\n", g_pop_name);

	/* Everything happens here */
	fprintf(f, "cd %s/%s/traffic\n", g_rrdpath, g_pop_name);

	while ((dp = readdir(dirp)))
	{
		/* Is it the RRD we are looking for? */
		i = strlen(dp->d_name);

		if (i < 4 || dp->d_name[0] == '.') continue;

		/* Only do the .rrd files, though not any that start with a T as they are converted already too */
		if (	strcmp(&dp->d_name[i-4], ".rrd") != 0 ||
			dp->d_name[0] == 'T')
		{
			fprintf(f, "# Ignoring %s [not .rrd or already T]\n", dp->d_name);
			continue;
		}

		/* Direct conversion? */
		if (	strcmp(dp->d_name, "uplink.rrd") == 0 ||
			strcmp(dp->d_name, "total.rrd") == 0)
		{
			for (d = 0; d < lengthof(dss); d++)
			{
				fprintf(f, "rrdtool tune %s -d %s:ABSOLUTE\n", dp->d_name, dss[d]);
			}

			continue;
		}

		/* Not a 'sixxs', 'gif' or 'tun' name, then we probably don't care */
		if (	strncmp(dp->d_name, "sixxs", 5) != 0 &&
			strncmp(dp->d_name, "gif", 3) != 0 &&
			strncmp(dp->d_name, "tun", 3) != 0)
		{
			fprintf(f, "# Ignoring %s [not sixxs, gif or tun]\n", dp->d_name);
			continue;
		}

		/* What number is in there? */
		for (tseq = j = 0; j < i; j++)
		{
			if (dp->d_name[j] < '0' || dp->d_name[j] > '9') continue;

			tseq *= 10;
			tseq += dp->d_name[j] - '0';
		}

		/* Do you have for me? */
		snprintf(q, sizeof(q), "SELECT tunnel_id "
					"FROM tunnels "
					"INNER JOIN pops ON tunnels.pop_id = pops.pop_id "
					"WHERE pop_name = '%s' "
					"AND tunnel_seq = %u", g_pop_name, tseq);

		/* Figure out which TID this rrd belongs too */
		if (!db_query(&db, q))
		{
			mdolog(LOG_WARNING, "[%s] Could not query for '%s' / %u\n", g_pop_name, dp->d_name, tseq);
			fprintf(f, "# Could not query for '%s' / %u\n", dp->d_name, tseq);
			continue;
		}

		res = mysql_store_result(db);
		j = mysql_num_rows(res);
		row = mysql_fetch_row(res);
		if (j == 1 && row)
		{
			tid = atoi(row[0]);
			if (tid != 0)
			{
				/* Rename the file */
				fprintf(f, "mv %s T%u.rrd\n", dp->d_name, tid);

				/* Convert all the datasets */
				for (d = 0; d < lengthof(dss); d++)
				{
					/* Change to a GAUGE */
					fprintf(f, "rrdtool tune T%u.rrd -d %s:ABSOLUTE\n", tid, dss[d]);
					converts++;
				}
			}
		}
		else
		{
			mdolog(LOG_WARNING, "[%s] Tunnel sequence %u for file %s is ambigiuous (%u matches), can't convert\n", g_pop_name, tseq, dp->d_name, j);
			fprintf(f, "# Unknown %s\n", dp->d_name);
		}

		db_suckrows(res);
	}

	closedir(dirp);

	/* Go through the ping directory and rename every RRD to the latency dir */
	snprintf(tmp, sizeof(tmp), "%s/%s/ping/", g_rrdpath, g_pop_name);
	if ((dirp = opendir(tmp)) == NULL)
	{
		mdolog(LOG_ERR, "[%s] Could not open directory %s, skipping for conversion\n", g_pop_name, tmp);
	}

	while (dirp && (dp = readdir(dirp)))
	{
		/* Is it the RRD we are looking for? */
		i = strlen(dp->d_name);

		if (i < 4 || dp->d_name[0] == '.') continue;

		/* Only do the .rrd files, though not any that start with a T as they are converted already too */
		if (	strcmp(&dp->d_name[i-4], ".rrd") != 0 ||
			dp->d_name[0] == 'T' ||
			strcmp(dp->d_name, "uplink.rrd") == 0 ||
			strcmp(dp->d_name, "total.rrd") == 0)
		{
			continue;
		}

		/* Find the first dot */
		for (j = 0; j < i; j++)
		{
			if (dp->d_name[j] != '.') continue;
			break;
		}

		/* First part is 4 long, then it is IPv6, otherwise IPv4 */
		if (j == 4)
		{
			for (j = 0; j < (i-4); j++)
			{
				tmp[j] = dp->d_name[j];
				if (tmp[j] == '.') tmp[j] = ':';
			}
			tmp[j] = '\0';

			/* Is it a tunnel? */
			r = snprintf(q, sizeof(q),
					"SELECT tunnel_id "
					"FROM tunnels "
					"INNER JOIN pops ON tunnels.pop_id = pops.pop_id "
					"WHERE pop_name = '%s' "
					"AND tunnel_ipv6_them = '%s'",
					g_pop_name, tmp);
			if (!snprintfok(r, sizeof(q)))
			{
				mdolog(LOG_WARNING, "[%s] Query too long: %s\n", g_pop_name, q);
				exit(0);
			}

			/* Figure out which TID this rrd belongs too */
			if (!db_query(&db, q))
			{
				mdolog(LOG_WARNING, "[%s] Could not query for '%s' / %s\n", g_pop_name, dp->d_name, tmp);
				/* Fail */
				exit(0);
			}

			res = mysql_store_result(db);
			j = mysql_num_rows(res);
			row = mysql_fetch_row(res);

			if (j == 1 && row)
			{
				tid = atoi(row[0]);
				if (tid != 0)
				{
					snprintf(tmp, sizeof(tmp), "%s/%s/ping/%s", g_rrdpath, g_pop_name, dp->d_name);
					snprintf(tmp2, sizeof(tmp2), "%s/%s/latency/T%u.rrd", g_rrdpath, g_pop_name, tid);
					rename(tmp, tmp2);
				}

				db_suckrows(res);
			}
			else if (j != 0)
			{
				db_suckrows(res);
				mdolog(LOG_WARNING, "[%s] Latency RRD %s is ambigiuous (%u matches), skipping\n", g_pop_name, dp->d_name, j);
			}
			else
			{
				db_suckrows(res);

				/* Maybe a PoP IP? */
				snprintf(q, sizeof(q),
						"SELECT pop_name "
						"FROM pops "
						"WHERE pop_ipv6 = '%s'",
						tmp);

				/* Figure out which TID this rrd belongs too */
				if (!db_query(&db, q))
				{
					mdolog(LOG_WARNING, "[%s] Could not query for '%s' / %s\n", g_pop_name, dp->d_name, tmp);
					/* Fail */
					exit(0);
				}

				res = mysql_store_result(db);
				j = mysql_num_rows(res);
				row = mysql_fetch_row(res);
				if (j == 1 && row)
				{
					snprintf(tmp, sizeof(tmp), "%s/%s/ping/%s", g_rrdpath, g_pop_name, dp->d_name);
					snprintf(tmp2, sizeof(tmp2), "%s/%s/latency/P%s.rrd", g_rrdpath, g_pop_name, row[0]);
					rename(tmp, tmp2);
				}
				else
				{
					/* mdolog(LOG_WARNING, "[%s] has ping RRD %s but it is not a PoP IPv6, skipping\n", g_pop_name, dp->d_name); */
				}

				db_suckrows(res);
			}
		}
		else
		{
			for (j = 0; j < i; j++)
			{
				tmp[j] = dp->d_name[j];
			}

			tmp[j] = '\0';

			/* Maybe a PoP IP? */
			snprintf(q, sizeof(q),
					"SELECT pop_name "
					"FROM pops "
					"WHERE pop_ipv4 = '%s'",
					tmp);

			/* Figure out which TID this rrd belongs too */
			if (!db_query(&db, q))
			{
				mdolog(LOG_WARNING, "[%s] Could not query for '%s' / %s\n", g_pop_name, dp->d_name, tmp);
				/* Fail */
				exit(0);
			}

			j = mysql_field_count(db);
			res = mysql_store_result(db);
			row = mysql_fetch_row(res);
			if (j == 1 && row)
			{
				snprintf(tmp, sizeof(tmp), "%s/%s/ping/%s", g_rrdpath, g_pop_name, dp->d_name);
				snprintf(tmp2, sizeof(tmp2), "%s/%s/latency/P%s.rrd", g_rrdpath, g_pop_name, row[0]);
				rename(tmp, tmp2);
			}
			else
			{
				/* mdolog(LOG_WARNING, "[%s] has ping RRD %s but it is not a PoP IPv4, skipping\n", g_pop_name, dp->d_name); */
			}

			db_suckrows(res);
		}
	}

	if (dirp) closedir(dirp);

	if (converts > 0)
	{
		/* Mark the PoP as converted */
		fprintf(f, "echo -n '%s conversion completed' >.rrdmode_v4\n", g_pop_name);
		fprintf(f, "echo -n 'RRD to v4 conversion of %s completed at ' && date\n", g_pop_name);

		/* Close her up, as all is done */
		fclose(f);

		/* Give it enough permissions */
		chmod(scriptname, 0755);

		/* Run the script */
		system(scriptname);

		/* Remove the script as we are done */
		unlink(scriptname);
	}
	else
	{
		/* No conversions needed */
		fclose(f);
		unlink(scriptname);

		/* Mark it as finished */
		snprintf(scriptname, sizeof(scriptname), "%s/%s/traffic/.rrdmode_v4", g_rrdpath, g_pop_name);
		f = fopen(scriptname, "w+");
		fprintf(f, "Didn't have anything to convert\n");
		fclose(f);
	}

	/* Ready to proceed */
	return true;
}

void collectstats(void);
void collectstats(void)
{
	char	buf[256];
	int	sockfd = -1;
	MYSQL	*db = NULL;

	/* First we need to check if the RRDs are already converted to gaugers */
	if (!checkv4rrd())
	{
		mdolog(LOG_WARNING, "[%s] Needs conversion to v4 RRD which has not completed yet\n", g_pop_name);
		return;
	}

	/* Reset RRD error count */
	g_rrd_errcnt = 0;

	/* First try to connect to the Management IP if there is one */
	if (g_pop_mgmt && strlen(g_pop_mgmt) > 0)
	{
		sockfd = sock_connect(buf, sizeof(buf), g_pop_mgmt, g_pop_service, AF_UNSPEC, SOCK_STREAM, 0, NULL, NULL);
		if (sockfd == -1)
		{
			mdolog(LOG_WARNING, "[%s] Couldn't connect to management address of %s:%s - %s\n",
				g_pop_name, g_pop_name, g_pop_service, buf);
		}
	}

	/* No management IP or that one failed, then try to connect over IPv6 + IPv4 based on DNS */
	if (sockfd == -1)
	{
		sockfd = sock_connect(buf, sizeof(buf), g_pop_name, g_pop_service, AF_UNSPEC, SOCK_STREAM, 0, NULL, NULL);
		if (sockfd == -1)
		{
			mdolog(LOG_WARNING, "[%s] Couldn't connect to address of %s:%s - %s\n",
				g_pop_name, g_pop_name, g_pop_service, buf);
		}
	}

	if (sockfd == -1) return;

	mdolog(LOG_DEBUG, "[%s] Connected...\n", g_pop_name);

	if (strcasecmp(g_pop_version, "v4") == 0)
	{
		collectstats4(sockfd, &db);
	}
	else
	{
		collectstats3(sockfd);
	}

	db_disconnect(&db);

	/* Close it */
	disconnect_client(&sockfd);
}

int main(int argc, char *argv[])
{
	int		i;
	struct tm	teem;
	time_t		tee;
	const char	q[] = "SELECT pop_name, pop_management_ip, pop_version "
				"FROM pops "
				"WHERE pop_enabled = 'Y' "
				"AND pop_running = 'Y' "
				"ORDER BY pop_name";
	MYSQL		*db = NULL;
	MYSQL_RES	*res;
	MYSQL_ROW	row;

	for (i = 1; i < argc; i++)
	{
		if (argv[i][0] != '-')
		{
			fprintf(stderr, "Expected switch (-) but not there for argument %u (%s)\n", i, argv[i]);
			return -1;
		}

		switch (argv[i][1])
		{
		case 'v':
			g_debug = true;
#ifndef DEBUG
			fprintf(stderr, "Not compiled with debugging options\n");
			return -1;
#endif
			break;

		default:
			fprintf(stderr, "Unknown option %c\n", argv[i][1]);
			fprintf(stderr, "popstatsd [-v]\n");
			return -1;
		}
	}

	/* Read our configuration */
	if (!db_readconfig()) return -1;

	if (!g_debug)
	{
		/* We are very nice */
		nice(19);

		/* Change to the sixxs user+group */
		setgid(1001);
		setuid(1008);

		/* Daemonize */
		i = fork();
		if (i < 0)
		{
			fprintf(stderr, "Couldn't fork\n");
			return -1;
		}

		/* Exit the mother fork */
		if (i != 0) return 0;

		/* Child fork */
		setsid();
		/* Cleanup stdin/out/err */
		freopen("/dev/null","r",stdin);
		freopen("/dev/null","w",stdout);
		freopen("/dev/null","w",stderr);

		/* Ignore SIGHUP's */
		signal(SIGHUP, SIG_IGN);

		/* Try to ignore SIGTERM/INT/KILL */
		signal(SIGTERM, SIG_IGN);
		signal(SIGINT, SIG_IGN);
		signal(SIGKILL, SIG_IGN);
	}

	/* Loop forever ;) */
	for (;;)
	{
		/* Ask for a list of the PoPs we want to gather stats from */
		if (db_query(&db, q))
		{
			res = mysql_store_result(db);

			if (mysql_num_rows(res) == 0)
			{
				mdolog(LOG_WARNING, "No PoPs that wanted their stats checked?\n");
			}
			else
			{
				while ((row = mysql_fetch_row(res)))
				{
					g_pop_name = row[0];
					g_pop_mgmt = row[1];
					g_pop_version = row[2];

					/* Collect The Statistics(tm) */
					collectstats();
				}
			}

			db_suckrows(res);
		}

		/* Get the current time */
		tee = time(NULL);
		gmtime_r(&tee, &teem);

		/* Sleep for the remaining time and thus run every xx mins */
		i = ((EVERY-(teem.tm_min % EVERY))*60) - teem.tm_sec;
		mdolog(LOG_DEBUG, "Sleeping for %u seconds (~= %u minutes) every=%u\n", i, i/60, EVERY);
		sleep(i);

		/*
		 * Examples of the above sleeper:
		 * 00:20:15 -> ((5-(20%5=0)=5)*60) - 15 = 5*60 - 15 = 285 = 04:45
		 * 00:20:00 -> ((5-(20%5=0)=5)*60) -  0 = 5*60 -  0 = 300 = 05:00
		 * 00:19:45 -> ((5-(19%5=4)=1)*60) - 45 = 1*60 - 45 =  15 = 00:15
		 * 00:17:15 -> ((5-(17%5=2)=3)*60) - 15 = 3*60 - 15 = 165 = 02:45
		 */
	}

	/* Indeed, we don't cleanup anything! ;) */
}

