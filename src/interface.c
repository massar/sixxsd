/**************************************
 SixXSd - SixXS PoP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
***************************************
 $Author: jeroen $
 $Id: interface.c,v 1.16 2006-03-22 17:40:34 jeroen Exp $
 $Date: 2006-03-22 17:40:34 $

 SixXSd Interface Management 
**************************************/

#include "sixxsd.h"

const char module_interface[] = "interface";
#define module module_interface

bool int_set_endpoint(struct sixxs_interface *iface, struct in_addr ipv4_them)
{
	/* Still the same? */
	if (memcmp(&iface->ipv4_them, &ipv4_them, sizeof(ipv4_them)) == 0) return true;

	/* XXX: Verify that the IPv4 address is not used by another (active) interface */

	/* Let the OS handler handle it */
	return os_int_set_endpoint(iface, ipv4_them);
}

bool int_set_state(struct sixxs_interface *iface, enum iface_state state)
{
        /* Swap DISABLED/DOWN state? */
	if (	(state == IFSTATE_DISABLED || state == IFSTATE_DOWN) &&
		(iface->state == IFSTATE_DISABLED || iface->state == IFSTATE_DOWN))
	{
		/* Only need to update the state */
		iface->state = state;
		return true;
	}

	return os_int_set_state(iface, state);
}

bool int_set_type(struct sixxs_interface *iface, enum iface_type type);
bool int_set_type(struct sixxs_interface *iface, enum iface_type type)
{
	bool restart = false;

	/* Don't change when it is already done */
	if (iface->type == type) return true;

	/* Mark it down (stops stuff) */
	if (iface->state == IFSTATE_UP)
	{
		restart = true;
		int_set_state(iface, IFSTATE_DOWN);
	}

	/* Modify the interface type and mark it unsynced */
	iface->type = type;
	iface->synced_link		= false;
	iface->synced_addr		= false;
	iface->synced_local		= false;
	iface->synced_remote		= false;
	iface->synced_subnet		= false;

	/* Mark it up when it was up */
	if (restart) int_set_state(iface, IFSTATE_UP);

	return true;
}

bool int_set_mtu(struct sixxs_interface *iface, unsigned int mtu);
bool int_set_mtu(struct sixxs_interface *iface, unsigned int mtu)
{
	if (iface->mtu == mtu) return true;

	/* We only limit the lower MTU here, anything higher can be set */
	if (mtu < 1280)
	{
		mdolog(LOG_ERR, "Ignoring setting of interface %s's MTU to %u which is smaller than IPv6 MTU of 1280\n", iface->name, mtu);
		return false;
	}

	/* Make sure that the kernel thinks the same thing directly */
	os_int_set_mtu(iface, mtu);
	
	return true;
}

/* Lame function as we are the AYIYA server so nothing needs
   to be sent to any other programs anyways ;) */
bool int_set_port(struct sixxs_interface *iface, unsigned int port)
{
	/* Still the same? */
	if (iface->ayiya_port == port) return true;
	
	/* Change the port */
	iface->ayiya_port = port;

	return true;
}

bool int_beat(struct sixxs_interface *iface)
{
	time_t tee = time(NULL);

	/* Update the last heartbeat */
	iface->hb_lastbeat = mktime(gmtime(&tee));

	/* Make it go up? (unless it is disabled) */
	if (iface->state != IFSTATE_DISABLED)
	{
		/* Up up and beyond! */
		int_set_state(iface, IFSTATE_UP);
	}

	return true;
}

bool int_set_password(struct sixxs_interface *iface, char *password);
bool int_set_password(struct sixxs_interface *iface, char *password)
{
	SHA_CTX sha1;

	if (!password)
	{
		mdolog(LOG_WARNING, "No password passed to set for interface %s/%u\n", iface->name, iface->interface_id);
		return false;
	}

	if (strlen(password) > (sizeof(iface->password)-2))
	{
		mdolog(LOG_WARNING, "Trying to set a too long password to interface %s/%u\n", iface->name, iface->interface_id);
		return false;
	}

	/* Password still the same? */
	if (strcmp(password, iface->password) == 0) return true;

	memset(iface->password, 0, sizeof(iface->password));
	memcpy(iface->password, password, strlen(password));

	/* Generate a SHA1 of the shared secret */
	SHA1_Init(&sha1);
	SHA1_Update(&sha1, (unsigned char *)iface->password, strlen(iface->password));
	SHA1_Final(iface->ayiya_hash, &sha1);

	return true;
}

struct sixxs_interface *int_get(unsigned int id)
{
	struct sixxs_interface *iface;

	if (id >= g_conf->max_interfaces)
	{
		mdolog(LOG_WARNING, "int_get() - %u out of range (>=%u)\n", id, g_conf->max_interfaces);
		return NULL;
	}
	
	OS_Mutex_Lock(&g_conf->mutex_interfaces, "int_get");
	iface = g_conf->interfaces + id;

	/* Init the mutex on first hit */
	if (iface->type == IFACE_UNSPEC)
	{
		OS_Mutex_Init(&iface->mutex);
	}

	/* XXX: Watch this one */
	OS_Mutex_Release(&g_conf->mutex_interfaces, "int_get");
	OS_Mutex_Lock(&iface->mutex, "int_get");

	return iface;
}

struct sixxs_interface *int_get_by_index(unsigned int id)
{
	unsigned int		i;
	struct sixxs_interface	*iface;

	OS_Mutex_Lock(&g_conf->mutex_interfaces, "int_get_by_index");
	for (i = 0; i < g_conf->max_interfaces; i++)
	{
		iface = g_conf->interfaces + i;
		if (iface->type == IFACE_UNSPEC) continue;
		if (iface->kernel_ifindex == id)
		{
			OS_Mutex_Release(&g_conf->mutex_interfaces, "int_get_by_index");
			OS_Mutex_Lock(&iface->mutex, "int_get_by_index");
			return iface;
		}
	}
	OS_Mutex_Release(&g_conf->mutex_interfaces, "int_get_by_index");

	return NULL;
}

/* Reconfigure (add or update) an interface */
bool int_reconfig(unsigned int id, struct in6_addr *ipv6_us, struct in6_addr *ipv6_them, int prefixlen, struct in_addr ipv4_them, enum iface_type type, enum iface_state state, unsigned int mtu, char *password)
{
	struct sixxs_interface *iface;

	if (type == IFACE_UNSPEC)
	{
		mdolog(LOG_ERR, "Can't configure to become an unspecified interface\n");
		return false;
	}

	/* Get the index */
	iface = int_get(id);
	if (!iface) return false;

	/* Already configured once ? */
	if (iface->type != IFACE_UNSPEC)
	{
		mdolog(LOG_INFO, "Reconfiguring interface %u\n", id);

		/*
		 * Assumption:
		 * - ipv6_them & ipv6_us & prefixlen don't change
		 */

		/* Changed Type? */
		int_set_type(iface, type);

		/* Changed State? */
		/* Don't turn down Heartbeat or AYIYA interfaces */
		if (iface->type == IFACE_PROTO41_HB || iface->type == IFACE_AYIYA)
		{
			/* Only try to change state when the new one is disabled/up or the old one is disabled */
			if (state == IFSTATE_DISABLED || state == IFSTATE_UP || iface->state == IFSTATE_DISABLED) int_set_state(iface, state);
		}
		else int_set_state(iface, state);

		/* Changed IPv4 endpoint? */
		if (type == IFACE_PROTO41) int_set_endpoint(iface, ipv4_them);

		/* Changed MTU? */
		int_set_mtu(iface, mtu);

		/* Changed password? */
		if (password) int_set_password(iface, password);
	}
	else
	{
		/* New interface thus assume not synced yet */
		iface->synced_link	= false;
		iface->synced_addr	= false;
		iface->synced_local	= false;
		iface->synced_remote	= false;
		iface->synced_subnet	= false;

		/* State is down */
		iface->state		= IFSTATE_DOWN;

		/* Fill it in */
		iface->interface_id	= id;
		iface->type		= type;
		iface->mtu		= mtu;
		iface->ttl		= 64;
		iface->ayiya_sport	= atoi(AYIYA_PORT);
		iface->ayiya_port	= atoi(AYIYA_PORT);

		memcpy(&iface->ipv4_them,	&ipv4_them,	sizeof(iface->ipv4_them));
		memcpy(&iface->ipv6_them,	ipv6_them,	sizeof(iface->ipv6_them));
		memcpy(&iface->ipv6_us,		ipv6_us,	sizeof(iface->ipv6_us));

		iface->prefixlen = prefixlen;

		/*
		 * TUN/TAP devices don't have any
		 * link local addresses and we want multicast and MLD to work
		 * thus we invent one based on the following:
		 *
		 * ipv6_us = 2001:0db8:1234:5678:    :    :    :0001
		 * ipv6_ll = fe80:    :    :    :0db8:1234:5678:0001
		 *
		 * Thus we ignore the first 16bits, take the following 48 bits
		 * and then add the last 16bits.
		 *
		 * As we are not 100% sure that this LL is unique we clear that bit.
		*/

		/* Link Local (fe80::/64) */
		iface->ipv6_ll.s6_addr[ 0] = 0xfe;
		iface->ipv6_ll.s6_addr[ 1] = 0x80;
		iface->ipv6_ll.s6_addr[ 2] = 0x00;
		iface->ipv6_ll.s6_addr[ 3] = 0x00;
		iface->ipv6_ll.s6_addr[ 4] = 0x00;
		iface->ipv6_ll.s6_addr[ 5] = 0x00;
		iface->ipv6_ll.s6_addr[ 6] = 0x00;
		iface->ipv6_ll.s6_addr[ 7] = 0x00;

		/* Clear the LL Unique Bit */
		iface->ipv6_ll.s6_addr[ 8] = iface->ipv6_us.s6_addr[ 2] & 0xfc;
		iface->ipv6_ll.s6_addr[ 9] = iface->ipv6_us.s6_addr[ 3];
		iface->ipv6_ll.s6_addr[10] = iface->ipv6_us.s6_addr[ 4];
		iface->ipv6_ll.s6_addr[11] = iface->ipv6_us.s6_addr[ 5];
		iface->ipv6_ll.s6_addr[12] = iface->ipv6_us.s6_addr[ 6];
		iface->ipv6_ll.s6_addr[13] = iface->ipv6_us.s6_addr[ 7];
		iface->ipv6_ll.s6_addr[14] = iface->ipv6_us.s6_addr[14];
		iface->ipv6_ll.s6_addr[15] = iface->ipv6_us.s6_addr[15];

		/* Configure a password ? */
		if (password) int_set_password(iface, password);

		/* Construct the devicename */
		snprintf(iface->name, sizeof(iface->name), "%s%u", g_conf->pop_tunneldevice, id);

		mdolog(LOG_INFO, "Initializing new interface %u: %s, type=%s, state=%s\n",
			id,
			iface->name,
			(type == IFACE_UNSPEC		? "invalid" :
			type == IFACE_IGNORE		? "ignore" :
			type == IFACE_PROTO41		? "proto-41" :
			type == IFACE_PROTO41_HB	? "proto-41-HB" :
			type == IFACE_TINC		? "tinc" :
			type == IFACE_AYIYA		? "AYIYA" : "?"),

			(state == IFSTATE_DISABLED	? "disabled" :
			state == IFSTATE_UP		? "up" :
			state == IFSTATE_DOWN		? "down" : "?")
			);

		/* Local address */
		pfx_reconfig(ipv6_us,	128, NULL,	true, false, true, false, iface);

		/* Remote address */
		pfx_reconfig(ipv6_them, 128, ipv6_us,	true, false, true, false, iface);

		/* Reconfigure the complete interface */
		int_set_state(iface, state);
	}

	OS_Mutex_Release(&iface->mutex, "int_reconfig");

	return true;
}

