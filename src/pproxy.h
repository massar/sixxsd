/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2015 All Rights Reserved
***********************************************************/

#ifndef PPROXY_H
#define PPROXY_H "SixXSd Port Proxy definitions"

#include "sixxsd.h"

#define SIXXSD_PPROXY_BASE		(16*1024)			/* Base port number */
#define SIXXSD_PPROXY_MAX		(4*1024)			/* Maximum number of ports */
#define SIXXSD_PPROXY_CONNECTIONS	(16)				/* Maximun number of connects */
#define SIXXSD_PPROXY_RESOLVE_TIMEOUT	(10*60)				/* 10 minutes */
#define SIXXSD_PPROXY_BUF_SIZE		2048				/* 2 KiB */

struct sixxsd_pproxy_conn
{
	SOCKET				remote;				/* Remote socket */
	char				buf_i[SIXXSD_PPROXY_BUF_SIZE];	/* Buffer input */
	char				buf_o[SIXXSD_PPROXY_BUF_SIZE];	/* Buffer output */
	uint64_t			off_in;				/* Offset input */
	uint64_t			off_out;			/* Offset output */
	uint16_t			portnum;			/* Port number */
	uint16_t			__padding[3];
};

struct sixxsd_pproxy
{
	uint32_t			pproxy_id;			/* The P<xxx> in the database */

	char				dest_name[NI_MAXHOST];		/* Destination hostname/IP */
	uint8_t				__padding[3];
	uint64_t			dest_port;			/* Destination Port */
	IPADDRESS			dest_ip;			/* Resolved IP */
	time_t				dest_lastlookup;		/* Last lookup */

	uint64_t			num_connections;		/* Number of connections */
	uint64_t			bytes_in, bytes_out;		/* Number of bytes sent */

	struct sixxsd_pproxy_conn	conn[SIXXSD_PPROXY_CONNECTIONS];
};

int pproxy_init(struct sixxsd_context *ctx);

#endif /* PPROXY_H */

