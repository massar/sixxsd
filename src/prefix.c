/**************************************
 SixXSd - SixXS POP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
***************************************
 $Author: jeroen $
 $Id: prefix.c,v 1.3 2005-01-31 17:06:26 jeroen Exp $
 $Date: 2005-01-31 17:06:26 $

 SixXSd Prefix Management
**************************************/

#include "sixxsd.h"

/********************************************************************
 Prefixes are known as 'routes' in most systems.
 but we name them differently as these also contain addresses
 that are used on tunnel interfaces.  
********************************************************************/

/* Maskbit. */
static u_char maskbit[] = {0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff};

// Is a_pfx a part/subnet of b_pfx?
bool pfx_issubnet(struct in6_addr *b_pfx, unsigned int b_len, struct in6_addr *a_pfx, unsigned int a_len)
{
	int offset, shift;

	/* Set both prefix's head pointer. */
	u_char *np = (u_char *)a_pfx;
	u_char *pp = (u_char *)b_pfx;
	
	// When the prefixlength of A is bigger as B's then it won't fit
	if (a_len > b_len) return false;

	offset = a_len / 8;
	shift =  a_len % 8;

	if (shift && (maskbit[shift] & (np[offset] ^ pp[offset])))
	{
		return false;
	}

	while (offset--)
	{
		if (np[offset] != pp[offset]) return false;
	}

	return true;
}

struct sixxs_prefix *pfx_get(struct in6_addr *ipv6_them, unsigned int prefixlen)
{
	struct sixxs_prefix	*pfx;
	unsigned int		i;

	// Walk through all the prefixes
	for (i = 0; i < g_conf->max_prefixes; i++)
	{
		pfx = g_conf->prefixes + i;
		//dolog(LOG_DEBUG, "pfx_get() %u -> %p\n", i, pfx);
		if (!pfx->valid) continue;

		if (pfx_issubnet(ipv6_them, prefixlen, &pfx->prefix, pfx->length))
		{
			return pfx;
		}
	}
	return NULL;
}

struct sixxs_prefix *pfx_new()
{
	struct sixxs_prefix	*pfx;
	unsigned int		i;

	// Walk through all the prefixes
	for (i = 0; i < g_conf->max_prefixes; i++)
	{
		pfx = g_conf->prefixes + i;
		if (!pfx->valid)
		{
			memset(pfx, 0, sizeof(*pfx));
			return pfx;
		}
	}
	return NULL;
}

void pfx_reconfig(struct in6_addr *prefix, unsigned int length, struct in6_addr *nexthop, bool enabled, bool is_tunnel, unsigned int interface_id)
{
	struct sixxs_prefix	*pfx;

	pfx = pfx_get(prefix, length);
	if (!pfx) pfx = pfx_new();

	if (!pfx)
	{
		dolog(LOG_ERR, "pfx_reconfig() - Could not get a new prefix\n");
		return;
	}

	// Mark the prefix as valid/inuse
	pfx->valid = true;

	memcpy(&pfx->prefix, prefix, sizeof(pfx->prefix));
	pfx->length = length;
	if (nexthop) memcpy(&pfx->nexthop, nexthop, sizeof(pfx->nexthop));
	pfx->is_tunnel = is_tunnel;
	pfx->interface_id = interface_id;
	pfx->enabled = enabled;
}
