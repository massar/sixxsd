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

const char module_subnet[] = "subnet";
#define module module_subnet

struct sixxsd_subnet *subnet_get(IPADDRESS *addr)
{
	struct sixxsd_subnets	*ss;
	unsigned int		i, bo;
	uint16_t		sid;

	for (i = 0; i <= g_conf->subnets_hi; i++)
	{
		ss = &g_conf->subnets[i];

		/* Only look at the first prefix_length bits */
		bo = ss->prefix_length / 8;
		if (memcmp(&ss->prefix, addr, bo) != 0) continue;

		/* The next 8 bits describe the subnet id */
		sid = addr->a8[bo];
		if (sid < lengthof(ss->subnet)) return &ss->subnet[sid];
		else
		{
			char buf[NI_MAXHOST];
			inet_ntopA(addr, buf, sizeof(buf));
			mdolog(LOG_ERR, "subnet_get(%s) is out of subnet range\n", buf);
		}
		break;
	}

	return NULL;
}

/*
 * 0	<prefix>		The Prefix
 * 1	<tunnel-id>		The Tunnel-ID (tid)
 * 2	<type>			{bgp|static} (ignored at the moment)
 */
static int subnet_cmd_set_config(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[]);
static int subnet_cmd_set_config(struct sixxsd_context *ctx, const unsigned int UNUSED argc, const char UNUSED *args[])
{
	IPADDRESS		ip;
	struct sixxsd_tunnel	*tun;
	struct sixxsd_subnet	*sub;
	unsigned int		tmp;
	uint16_t		tid;

	if (!inet_ptonA(args[0], &ip, NULL))
	{
		ctx_printf(ctx, "Invalid IPv6 prefix (%s)\n", args[0]);
		return 400;
	}

	sub = subnet_get(&ip);
	if (!sub)
	{
		ctx_printf(ctx, "Route %s with gateway %s doesn't have a master subnet\n", args[0], args[1]);
		return 400;
	}

	if (sscanf(args[1], "%x", &tmp) != 1)
	{
		ctx_printf(ctx, "Tunnel-ID %s is not a number\n", args[1]);
		return 400;
	}
	tid = tmp;

	tun = tunnel_grab(tid);
	if (!tun || tun->state == SIXXSD_TSTATE_NONE)
	{
		ctx_printf(ctx, "Tunnel %s for subnet %s not found\n", args[1], args[0]);
		return 400;
	}

	sub->tunnel_id = tid;

	ctx_printf(ctx, "Accepted Route %s via %s\n", args[0], args[1]);
	return 200;
}

struct ctx_menu ctx_menu_subnet_set[] =
{
	{"set",		NULL,			0,0,	NULL,					NULL },
	{"config",	subnet_cmd_set_config,	3,3,	"<prefix> <tunnel-id> <type>",		"Configure a subnet" },
	{NULL,		NULL,			0,0,	NULL,					NULL },
};

CONTEXT_MENU(subnet_set)
CONTEXT_CMD(subnet_set)

struct ctx_menu ctx_menu_subnet[] =
{
	{"subnet",	NULL,			0,0,	NULL,					NULL },
	{"set",		ctx_cmd_subnet_set,	0,-1,	CONTEXT_SUB,				"Set configuration information" },
	{NULL,		NULL,			0,0,	NULL,					NULL },
};

CONTEXT_CMD(subnet)

