/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2013 All Rights Reserved
***********************************************************/

#ifndef CONTEXT_H
#define CONTEXT_H LI42

#include "sixxsd.h"

struct ctx_menu;

/* A ctx, which is passed around, allowing output/messages etc from functions */
struct sixxsd_context
{
	mutex			mutex;				/* Mutex for locking debugging + output */

	uint64_t		bufferfilled;			/* How far we have written inside the buffer */
	uint64_t		buffersize;			/* Size of the buffer */
	char			*buffer;			/* 50MB buffer */

	struct ctx_menu		*menu[10];			/* Path of menu's we took */
	uint64_t		menu_depth;			/* Depth of the menu we are at */

	uint64_t		debugging_tunnels;		/* How many tunnels we are debugging with this session */

	SOCKET			socket;				/* The socket for output messages/warnings/etc */
	IPADDRESS		ip;				/* The remote address of this context */
};

struct ctx_menu
{
	const char	*cmd;
	int		(*func)(struct sixxsd_context *ctx, const unsigned int argc, const char *args[]);
	int32_t		args_min;
	int32_t		args_max;
	const char	*options;
	const char	*description;
};

VOID ctx_init(struct sixxsd_context *ctx);
VOID ctx_exit(struct sixxsd_context *ctx);

#define ctx_lock(ctx) mutex_lock(ctx->mutex)
#define ctx_release(ctx); mutex_release(ctx->mutex)

VOID ctx_printedfA(struct sixxsd_context *ctx, int errnum, const char *ATTR_RESTRICT fmt, va_list ap) ATTR_FORMAT(printf, 3, 0);
VOID ctx_printef(struct sixxsd_context *ctx, int errnum, const char *ATTR_RESTRICT fmt, ...) ATTR_FORMAT(printf, 3, 4);
VOID ctx_printf(struct sixxsd_context *ctx, const char *ATTR_RESTRICT fmt, ...) ATTR_FORMAT(printf, 2, 3);
VOID ctx_printdf(struct sixxsd_context *ctx, const char *ATTR_RESTRICT fmt, ...) ATTR_FORMAT(printf, 2, 3);
VOID ctx_printxf(struct sixxsd_context *ctx, const char *ATTR_RESTRICT fmt, ...) ATTR_FORMAT(printf, 2, 3);
VOID ctx_printxdf(struct sixxsd_context *ctx, const char *ATTR_RESTRICT fmt, ...) ATTR_FORMAT(printf, 2, 3);
VOID ctx_flush(struct sixxsd_context *ctx, int code);
const char *ctx_get_string(struct sixxsd_context *ctx);

int ctx_showpacket(struct sixxsd_context *ctx, const uint8_t *packet, const unsigned int len);
int ctx_exec(struct sixxsd_context *ctx, const char *args, BOOL mainmenu, const char *precmd);
int ctx_shell(struct sixxsd_context *ctx, const char *args);
VOID ctx_popmenu(struct sixxsd_context *ctx);

/* Submenu's of the main commands */
int ctx_commandmenu(struct sixxsd_context *ctx, const unsigned int argc, const char *args[], struct ctx_menu *menu);
int ctx_command(struct sixxsd_context *ctx, const char *command);

#define CONTEXT_SUB (char *)-1

/* Defined close to the menu definition itself */
#define CONTEXT_CMD(submenu)										\
int ctx_cmd_##submenu(struct sixxsd_context *ctx, const unsigned int argc, const char *args[])	\
{													\
	return ctx_commandmenu(ctx, argc, args, ctx_menu_##submenu);				\
}

/* Used below, to reference the above */
#define CONTEXT_MENU(submenu)										\
int ctx_cmd_##submenu(struct sixxsd_context *ctx, const unsigned int argc, const char *args[]);

/* The main menu */
extern struct ctx_menu ctx_menu_main[13];		/* sixxsd.c */

/* All the submenu's */
CONTEXT_MENU(cmd)
CONTEXT_MENU(set)
CONTEXT_MENU(pop)
CONTEXT_MENU(subnet)
CONTEXT_MENU(tunnel)

#endif
