/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net
 (C) Copyright SixXS 2000-2011 All Rights Reserved
************************************************************
 $Author: $
 $Id: $
 $Date: $
***********************************************************/

#ifndef COMMON_EXTRA_H
#define COMMON_EXTRA_H N47H

#include "common.h"

/* Logging & Management functions */
VOID showlog(int f, unsigned int max);
VOID doelogA(int level, int errnum, const char *module, const char *ATTR_RESTRICT fmt, va_list ap) ATTR_FORMAT(printf, 4, 0);

#define mdoelogA(level, errnum, fmt, ap) doelogA(level, errnum, module, fmt, ap)
#define mdoelog(level, errnum, ...) doelog(level, errnum, module, __VA_ARGS__)
#define mdologA(level, fmt, ap) doelogA(level, 0, module, fmt, ap)
#define mdolog(level, ...) dolog(level, module, __VA_ARGS__)

/* Module Logging shortcuts */
#ifdef DEBUG
#define ddolog(module, ...) dolog(LOG_DEBUG, module, __VA_ARGS__)
#define ddoelog(module, errnum, ...) doelog(LOG_DEBUG, errnum, module, __VA_ARGS__)
#define mddolog(...) ddolog(module, __VA_ARGS__)
#define mddoelog(errnum, ...) ddoelog(module, errnum, __VA_ARGS__)
#else
#define ddolog(...) {}
#define ddoelog(...) {}
#define mddolog(...) {}
#define mddoelog(...) {}
#endif

/* Parsing functions */
int parseargs(struct sixxsd_context *ctx, char *buf, const char *args[], unsigned int maxargc);

/* parseline() rules */
enum pl_ruletype
{
	PLRT_STRING,		/* Offset points to a String (strdup()) */
	PLRT_STR128,		/* Offset points to a String (char string[128]) */
	PLRT_STR256,		/* Offset points to a String (char string[256]) */
	PLRT_STR512,		/* Offset points to a String (char string[512]) */
	PLRT_STR2048,		/* Offset points to a String (char string[2048]) */
	PLRT_UINT32,		/* Offset points to a uint32_t */
	PLRT_UINT64,		/* Offset points to a uint64_t */
	PLRT_BOOL,		/* Offset points to a Boolean. */
	PLRT_IP,		/* Offset points to an IP address (char string[16]) */
	PLRT_END		/* End of rules */
};

struct pl_rule
{
	const char              *title;
	unsigned int            type;
	unsigned int		offset;
};

int writefile(struct sixxsd_context *ctx, const char *filename, struct pl_rule *rules, PTR *data);
int parseline(struct sixxsd_context *ctx, char *line, const char *split, struct pl_rule *rules, PTR *data);
int sixxsd_strftime(struct sixxsd_context *ctx, char *buf, unsigned int buflen, const char *format, struct tm *teem);

/* Networking functions */
SOCKET use_uri_ctx(struct sixxsd_context *ctx, BOOL doconnect, const char *uri, const char *defaultservice, struct socketpool *pool, uint32_t tag);

#endif

