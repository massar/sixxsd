/**************************************
 SixXSd - SixXS PoP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
***************************************
 $Author: jeroen $
 $Id: prefix.c,v 1.11 2006-03-02 13:46:54 jeroen Exp $
 $Date: 2006-03-02 13:46:54 $

 SixXSd Prefix Management
**************************************/

#include "sixxsd.h"

const char module_prefix[] = "prefix";
#define module module_prefix

/********************************************************************
 Prefixes are known as 'routes' in most systems.
 but we name them differently as these also contain addresses
 that are used on tunnel interfaces.  
********************************************************************/

/* Maskbit. */
static u_char maskbit[] = {0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff};

/* Is a_pfx a part/subnet of b_pfx? */
bool pfx_issubnet(struct in6_addr *a_pfx, unsigned int a_len, struct in6_addr *b_pfx, unsigned int b_len)
{
	int offset, shift;

	/* Set both prefix's head pointer. */
	u_char *np = (u_char *)a_pfx;
	u_char *pp = (u_char *)b_pfx;

	/*
	 * When the prefixlength of A is bigger as B's then it won't fit
	 *  a   b
	 * 128  48 -> fits             >
	 *  48  48 -> fits             =
	 *   0  48 -> doesn't fit      <
	 */
	if (a_len < b_len) return false;

	/* 
	 * Only check the bits that matter
	 *  a   b
	 * 128 128 -> everything
	 * 128  48 -> only the first 48 bits
	 *  48  48 -> only the first 48 bits
	 *
	 * Depends on b_len
	 */
	offset = b_len / 8;
	shift =  b_len % 8;

	/* Check the last few none-8-bit-aligned bits first (easy and fast to check) */
	if (shift && (maskbit[shift] & (np[offset] ^ pp[offset])))
	{
		return false;
	}

	/* Check the rest */
	while (offset--)
	{
		if (np[offset] != pp[offset]) return false;
	}

	return true;
}

struct sixxs_prefix *pfx_getA(struct in6_addr *ipv6_them, unsigned int prefixlen, bool empty);
struct sixxs_prefix *pfx_getA(struct in6_addr *ipv6_them, unsigned int prefixlen, bool empty)
{
	struct sixxs_prefix	*pfx;
	unsigned int		i;

	/* Walk through all the prefixes */
	for (i = 0; i < g_conf->max_prefixes; i++)
	{
		pfx = g_conf->prefixes + i;
		/* mddolog("pfx_get() %u -> %p\n", i, pfx); */
		if (!pfx->valid)
		{
			if (empty)
			{
				memset(pfx, 0, sizeof(*pfx));
				OS_Mutex_Init(&pfx->mutex);
				OS_Mutex_Lock(&pfx->mutex, "pfx_getA(1)");
				pfx->valid = false;
				return pfx;
			}
			break;
		}

		if (	prefixlen == pfx->length &&
			memcmp(ipv6_them, &pfx->prefix, 16) == 0)
		{
			OS_Mutex_Lock(&pfx->mutex, "pfx_getA(2)");
			return pfx;
		}
	}

	return NULL;
}

struct sixxs_prefix *pfx_get(struct in6_addr *ipv6_them, unsigned int prefixlen)
{
	struct sixxs_prefix *pfx;

	OS_Mutex_Lock(&g_conf->mutex, "pfx_get()");
	pfx = pfx_getA(ipv6_them, prefixlen, false);
	OS_Mutex_Release(&g_conf->mutex, "pfx_get()");
	return pfx;
}

void pfx_reconfig(struct in6_addr *prefix, unsigned int length, struct in6_addr *nexthop, bool enabled, bool ignore, bool is_tunnel, bool is_popprefix, struct sixxs_interface *iface)
{
	struct sixxs_prefix	*pfx, *p;
	bool			isnew;

	OS_Mutex_Lock(&g_conf->mutex, "pfx_reconfig");
	pfx = pfx_getA(prefix, length, true);
	OS_Mutex_Release(&g_conf->mutex, "pfx_reconfig");

	if (!pfx)
	{
		mdolog(LOG_ERR, "pfx_reconfig() - Could not get a new prefix\n");
		return;
	}

	/* New one? */
	isnew = !pfx->valid;

	/* Mark the prefix as valid/inuse */
	pfx->valid = true;

	memcpy(&pfx->prefix, prefix, sizeof(pfx->prefix));
	pfx->length = length;
	if (nexthop) memcpy(&pfx->nexthop, nexthop, sizeof(pfx->nexthop));
	pfx->is_tunnel = is_tunnel;
	pfx->is_popprefix = is_popprefix;
	pfx->enabled = enabled;
	pfx->ignore = ignore;
	pfx->interface_id = iface->interface_id;

	if (iface->prefixes)
	{
		for (p = iface->prefixes; p; p = p->next)
		{
			if (p == pfx) break;
		}
	}
	else p = NULL;

	if (p != pfx)
	{
		/* Link the prefix into the interface list */
		if (!iface->prefixes) pfx->next = NULL;
		else pfx->next = iface->prefixes;
		iface->prefixes = pfx;
	}
	
	OS_Mutex_Release(&pfx->mutex, "pfx_reconfig");

	if (isnew)
	{
		char buf[100];
		inet_ntop(AF_INET6, &pfx->prefix, buf, sizeof(buf));
		mddolog("Added Prefix %s/%u\n", buf, length);
	}

	/* Sync the route */
	os_sync_routes(iface);
}

