/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2013 All Rights Reserved
***********************************************************/

#ifndef ROUTE_H
#define ROUTE_H "SixXSd Route definitions"

#include "sixxsd.h"

struct sixxsd_subnet
{
	uint16_t			tunnel_id;			/* Tunnel ID */
};

struct sixxsd_subnets
{
	IPADDRESS			prefix;				/* The prefix */
	uint8_t				prefix_length;			/* Length of the prefix ('/48 with /56s' or '/40 with /48s') */

	char				prefix_asc[NI_MAXHOST];		/* Cached textual representation of prefix */
	uint8_t				__padding[6];

	BOOL				online;				/* Did we tell the kernel about it? */

	struct sixxsd_subnet		subnet[256];			/* The subnets (256x /56s or /48s) */
};

struct sixxsd_subnet *subnet_get6(IPADDRESS *addr);

#endif /* ROUTE_H */

