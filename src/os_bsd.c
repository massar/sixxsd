/**************************************
 SixXSd - SixXS PoP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
***************************************
 $Author: jeroen $
 $Id: os_bsd.c,v 1.14 2008-02-18 21:33:11 jeroen Exp $
 $Date: 2008-02-18 21:33:11 $

 SixXSd - BSD specific code
**************************************/

#include "sixxsd.h"

const char module_os[] = "os_bsd";
#define module module_os

/* Temporary nasty hack against FBSD boxes crashing */
/* #define WAITPATCH() usleep(2000) */
#define WAITPATCH() {}

int os_kernelsocket;

bool os_initialized = false;

/* OS Helper functions */
void os_exec(const char *fmt, ...) ATTR_FORMAT(printf, 1, 2);
void os_exec(const char *fmt, ...)
{
	char buf[1024];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	mddolog("#### os_exec(\"%s\")\n", buf);
	system(buf);
	va_end(ap);
}

/* call ioctl system call */
int if_ioctl(int family, u_long request, caddr_t buffer);
int if_ioctl(int family, u_long request, caddr_t buffer)
{
	int sock = 0;
	int ret = 0;
	int err = 0;

	sock = socket(family, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		char buf[128];
		memset(buf, 0, sizeof(buf));
		strerror_r(errno, buf, sizeof(buf));
		mdolog(LOG_ERR, "Couldn't create a socket for IOCTL's: %s (%d)\n", buf, errno);
		exit(-1);
	}

	if ((ret = ioctl(sock, request, buffer)) < 0)
	{
		err = errno;
	}
	close (sock);

	if (ret < 0)
	{
		errno = err;
		return ret;
	}
	return 0;
}


/* get interface index number */
unsigned int if_get_ifindex_byname(const char *iface);
unsigned int if_get_ifindex_byname(const char *iface)
{
	struct ifreq ifreq;

	memset(&ifreq, 0, sizeof(struct ifreq));
	strncpy(ifreq.ifr_name, iface, IFNAMSIZ);

	if (if_ioctl(AF_INET, SIOCGIFINDEX, (caddr_t)&ifreq) < 0)
	{
		mdolog(LOG_WARNING, "Can't lookup index of %s by ioctl(SIOCGIFINDEX)\n", iface);
		return 0;
	}

	return ifreq.ifr_index;
}


/* Note: OpenBSD doesn't support renames */
bool os_int_rename(struct sixxs_interface *iface, bool back)
{
#ifdef _OPENBSD
	iface = iface;
	back = back;
#else
	char		tmp[128], desc[256];
	struct ifreq	ifr;
	SOCKET		s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s >= 0)
	{
		memset(&ifr, 0, sizeof(ifr));
		if (!back)
		{
			snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "tun%u", iface->interface_id);
			ifr.ifr_data = iface->name;
		}
		else
		{
			snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface->name);
			snprintf(tmp, sizeof(tmp), "tun%u", iface->interface_id);
			ifr.ifr_data = tmp;
		}

		if (ioctl(s, SIOCSIFNAME, &ifr) != 0)
		{
			if (back) snprintf(tmp, sizeof(tmp), "tun%u", iface->interface_id);
			else snprintf(tmp, sizeof(tmp), "gif%u", iface->interface_id);

			/* Check if the name is already correct */
			if (if_get_ifindex_byname(tmp) == 0)
			{
				memset(desc, 0, sizeof(desc));
				strerror_r(errno, desc, sizeof(desc));
				mdolog(LOG_ERR, "Couldn't set %sinterface name of tun%u to %s/%u: %s (%d)\n", back ? "back " : "", iface->interface_id, iface->name, iface->kernel_ifindex, desc, errno);
				close(s);
				return false;
			}
		}
	}
	else
	{
		memset(desc, 0, sizeof(desc));
		strerror_r(errno, desc, sizeof(desc));
		mdolog(LOG_ERR, "Couldn't create socket for renaming %stun%u to %s/%u: %s (%d)\n", back ? "back " : "", iface->interface_id, iface->name, iface->kernel_ifindex, desc, errno);
		close(s);
		return false;
	}

	close(s);
#endif

	return true;
}

/* Convert struct in6_addr netmask into integer */
unsigned int ip_masklen(void *netmask, unsigned int maxlen);
unsigned int ip_masklen(void *netmask, unsigned int maxlen)
{  
	unsigned int	len = 0;
	unsigned char	val, *pnt;

	pnt = (unsigned char *)netmask;
	while ((*pnt == 0xff) && len < maxlen)
	{
		len += 8;
		pnt++;
	}

	if (len < maxlen)
	{
		val = *pnt;
		while (val && len < maxlen)
		{
			len++;
			val <<= 1;
		}
	}
	return len;
}

/* clear and set interface name string */
void ifreq_set_name(struct ifreq *ifreq, struct sixxs_interface *iface);
void ifreq_set_name(struct ifreq *ifreq, struct sixxs_interface *iface)
{   
	if (iface) strncpy(ifreq->ifr_name, iface->name, IFNAMSIZ);
	else mddolog("ifreq_set_name() got passed a NULL iface\n");
}

/* get interface flags */
void if_get_flags(struct sixxs_interface *iface);
void if_get_flags(struct sixxs_interface *iface)
{
	int		ret;
	struct ifreq	ifreq;

	if (!iface)
	{
		mddolog("if_get_flags() got passed a NULL iface\n");
		return;
	}

	memset(&ifreq, 0, sizeof(struct ifreq));
	ifreq_set_name(&ifreq, iface);

	ret = if_ioctl(AF_INET, SIOCGIFFLAGS, (caddr_t)&ifreq);
	if (ret < 0)
	{
		char buf[128];
		memset(buf, 0, sizeof(buf));
		strerror_r(errno, buf, sizeof(buf));
		mdolog(LOG_ERR, "Couldn't get interface flags for interface %u/%s: %s (%d)\n", iface->interface_id, iface->name, buf, errno);
		return;
	}
	iface->kernel_flags = ifreq.ifr_flags & 0x0000ffff;
}

/* get interface index number */
unsigned int if_get_ifindex(struct sixxs_interface *iface);
unsigned int if_get_ifindex(struct sixxs_interface *iface)
{
	struct ifreq ifreq;

	if (!iface)
	{
		mddolog("if_get_mtu() got passed a NULL iface\n");
		return 0;
	}

	memset(&ifreq, 0, sizeof(struct ifreq));
	ifreq_set_name(&ifreq, iface);

	if (if_ioctl(AF_INET, SIOCGIFMTU, (caddr_t)&ifreq) < 0)
	{
		mdolog(LOG_WARNING, "Can't lookup mtu by ioctl(SIOCGIFMTU)\n");
		return 0;
	}
	return ifreq.ifr_mtu;
}

/* get interface MTU */
unsigned int if_get_mtu(struct sixxs_interface *iface);
unsigned int if_get_mtu(struct sixxs_interface *iface)
{
	struct ifreq ifreq;

	if (!iface)
	{
		mddolog("if_get_mtu() got passed a NULL iface\n");
		return 0;
	}

	memset(&ifreq, 0, sizeof(struct ifreq));
	ifreq_set_name(&ifreq, iface);

	if (if_ioctl(AF_INET, SIOCGIFMTU, (caddr_t)&ifreq) < 0)
	{
		mdolog(LOG_WARNING, "Can't lookup mtu by ioctl(SIOCGIFMTU)\n");
		return 0;
	}

	return ifreq.ifr_mtu;
}
  
/* Set interface flags */
int if_set_flags(struct sixxs_interface *iface, unsigned long flags);
int if_set_flags(struct sixxs_interface *iface, unsigned long flags)
{
	int ret;
	struct ifreq ifreq;

	if (!iface)
	{
		mddolog("if_set_flags() got passed a NULL iface\n");
		return 0;
	}

	memset(&ifreq, 0, sizeof(struct ifreq));
	ifreq_set_name(&ifreq, iface);
	ifreq.ifr_flags = iface->kernel_flags;
	ifreq.ifr_flags |= flags;

	ret = if_ioctl(AF_INET, SIOCSIFFLAGS, (caddr_t)&ifreq);
	if (ret < 0)
	{
		char buf[128];
		memset(buf, 0, sizeof(buf));
		strerror_r(errno, buf, sizeof(buf));
		mdolog(LOG_INFO, "can't set interface flags for interface %u/%s: %s (%d)\n", iface->interface_id, iface->name, buf, errno);
		return ret;
	}
	return 0;
}


/* Configure interfaces */
bool os_sync_link_up(struct sixxs_interface *iface);
bool os_sync_link_up(struct sixxs_interface *iface)
{
	/* Only when syncing */
	if (!g_conf->do_sync || iface->synced_link) return true;

	/* Create the interface */
	if (	iface->type == IFACE_PROTO41 ||
		iface->type == IFACE_PROTO41_HB)
	{
		char ipv4_us[100], ipv4_them[100];

		inet_ntop(AF_INET, &iface->ipv4_us, ipv4_us, sizeof(ipv4_us));
		inet_ntop(AF_INET, &iface->ipv4_them, ipv4_them, sizeof(ipv4_them));

		os_exec(
			"/sbin/ifconfig %s create",
			iface->name);

		os_exec(
			"/sbin/ifconfig %s tunnel %s %s",
			iface->name,
			ipv4_us,
			ipv4_them);
	}
	else if (iface->type == IFACE_AYIYA)
	{
#ifdef _OPENBSD
		/* OpenBSD doesn't support device renames thus name the device tunX */
		snprintf(iface->name, sizeof(iface->name), "tun%u", iface->interface_id);

		/* OpenBSD requires one to explicitly create the tunnel device */
		os_exec(
			"/sbin/ifconfig %s create",
			iface->name);

		/* Make the device node so that we can access it */
		os_exec(
			"mknod /dev/%s c 40 %u",
			iface->name,
			iface->interface_id);
#endif

		if (!ayiya_start(iface)) return false;
	}

	/* Mark the interface up + set MTU */
	os_exec(
		"/sbin/ifconfig %s mtu %u up",
		iface->name,
		iface->mtu);

	return true;
}

/* Mark interface down */
bool os_sync_link_down(struct sixxs_interface *iface);
bool os_sync_link_down(struct sixxs_interface *iface)
{
	/* Only when syncing */
	if (!g_conf->do_sync || !iface->synced_link) return true;

	os_exec(
		"/sbin/ifconfig %s down",
		iface->name);

	WAITPATCH();

	if (	iface->type == IFACE_PROTO41 ||
		iface->type == IFACE_PROTO41_HB)
	{
/*
		os_exec(
			"/sbin/ifconfig %s destroy",
			iface->name);
*/
	}
	else if (iface->type == IFACE_AYIYA)
	{
		ayiya_stop(iface);
	}

	return true;
}


/* Add addresses to the interface */
bool os_sync_address_up(struct sixxs_interface *iface);
bool os_sync_address_up(struct sixxs_interface *iface)
{
	char addr[100];

	/* Only when syncing */
	if (g_conf->do_sync && !iface->synced_addr)
	{
		inet_ntop(AF_INET6, &iface->ipv6_us, addr, sizeof(addr));
		os_exec(
			"/sbin/ifconfig %s inet6 %s prefixlen %u alias",
			iface->name,
			addr,
			/* we only route /128 tunnels */
			128);
	}

	return true;
}

bool os_sync_address_down(struct sixxs_interface *iface);
bool os_sync_address_down(struct sixxs_interface *iface)
{
	char addr[100];

	/* Only when syncing */
	if (g_conf->do_sync && iface->synced_addr)
	{
		mddolog("os_sync_address_down()\n");
		inet_ntop(AF_INET6, &iface->ipv6_us, addr, sizeof(addr));
		os_exec(
			"/sbin/ifconfig %s inet6 %s prefixlen %u -alias",
			iface->name,
			addr,
			128);

		iface->synced_addr = false;
		iface->synced_local = false;
		WAITPATCH();
	}

	return true;
}

bool os_sync_remote_up(struct sixxs_interface *iface);
bool os_sync_remote_up(struct sixxs_interface *iface)
{
	char us[100], them[100];

	/* Only when syncing */
	if (g_conf->do_sync && !iface->synced_remote)
	{
		inet_ntop(AF_INET6, &iface->ipv6_us, us, sizeof(us));
		inet_ntop(AF_INET6, &iface->ipv6_them, them, sizeof(them));
		os_exec(
			"/sbin/route add -inet6 %s -prefixlen %u %s",
			them,
			/* we only route /128 tunnels */
			128,
			us);
	}

	return true;
}

bool os_sync_route_up(struct sixxs_interface *iface);
bool os_sync_route_up(struct sixxs_interface *iface)
{
	char			them[100], subnet[100];
	struct sixxs_prefix	*pfx;

	/* Only when syncing */
	if (!g_conf->do_sync || iface->synced_subnet) return true;

	/* null0 on BSD can be done using the 'reject' flag */
	if (iface->type == IFACE_NULL) strncpy(them, "::1 -reject", sizeof(them));
	else inet_ntop(AF_INET6, &iface->ipv6_them, them, sizeof(them));

	/* Make sure we account for all subnets to be up */
	iface->subnets_got = 0;
	iface->subnets_up = 0;

	/* Sync subnets over this tunnel */
	for (pfx = iface->prefixes; pfx; pfx = pfx->next)
	{
		if (pfx->is_tunnel) continue;

		iface->subnets_got++;

		if (pfx->synced)
		{
			/* Count this one as being up */
			iface->subnets_up++;
			continue;
		}

		/* Add a route for this subnet */
		inet_ntop(AF_INET6, &pfx->prefix, subnet, sizeof(subnet));
		os_exec(
			"/sbin/route add -inet6 %s -prefixlen %u %s",
			subnet,
			pfx->length,
			them);
	}

	return true;
}

bool os_sync_route_down(struct sixxs_interface *iface);
bool os_sync_route_down(struct sixxs_interface *iface)
{
	char them[100], subnet[100];
	struct sixxs_prefix *pfx;

	inet_ntop(AF_INET6, &iface->ipv6_them, them, sizeof(them));

	/* Sync subnets over this tunnel */
	for (pfx = iface->prefixes; pfx; pfx = pfx->next)
	{
		if (pfx->is_tunnel || !pfx->synced) continue;

		mddolog("os_sync_route_down\n");
		inet_ntop(AF_INET6, &pfx->prefix, subnet, sizeof(subnet));
		os_exec(
			"/sbin/route delete -inet6 %s -prefixlen %u %s",
			subnet,
			pfx->length,
			them);
	}
	iface->synced_subnet = false;
	/* We marked them all down */
	iface->subnets_up = 0;
	WAITPATCH();
	return true;
}

bool os_sync_remote_down(struct sixxs_interface *iface);
bool os_sync_remote_down(struct sixxs_interface *iface)
{
	char them[100];

	/* Only when syncing and this was synced */
	if (g_conf->do_sync && iface->synced_remote)
	{
		inet_ntop(AF_INET6, &iface->ipv6_them, them, sizeof(them));

		mddolog("os_sync_remote_down\n");
		os_exec(
			"/sbin/route delete -inet6 %s -prefixlen %u",
			them,
			/* we only route /128 tunnels */
			128);

		iface->synced_remote = false;
	}
	WAITPATCH();
	return true;
}

bool os_sync_routes(struct sixxs_interface *iface)
{
	if (!g_conf->do_sync) return true;

	if (iface->state == IFSTATE_DISABLED || iface->state == IFSTATE_DOWN)
	{
		os_sync_route_down(iface);
	}
	else /* IFSTATE_UP */
	{
		os_sync_route_up(iface);
	}
	return true;
}

bool os_int_set_state(struct sixxs_interface *iface, enum iface_state state)
{
	/* Set the new state */
	iface->state = state;

	/* Don't actually sync */
	if (!g_conf->do_sync) return true;

	if (state == IFSTATE_DISABLED || state == IFSTATE_DOWN)
	{
		/* Take her DOWN */
		os_sync_route_down(iface);
		os_sync_remote_down(iface);
		os_sync_address_down(iface);
		os_sync_link_down(iface);
	}
	else if (state == IFSTATE_UP)
	{
		/* UP she goes */
		os_sync_link_up(iface);
	}

	return true;
}

bool os_int_set_endpoint(struct sixxs_interface *iface, struct in_addr ipv4_them)
{
	/* Set the new endpoint */
	memcpy(&iface->ipv4_them, &ipv4_them, sizeof(ipv4_them));

	/* We only interface with the OS for proto-41 tunnels */
	if (	iface->type != IFACE_PROTO41 &&
		iface->type != IFACE_PROTO41_HB)
	{
		return true;
	}

	/* Only when syncing */
	if (g_conf->do_sync && iface->state == IFSTATE_UP)
	{
		/* Link not synced? */
		if (!iface->synced_link)
		{
			/* Set the interface up */
			os_int_set_state(iface, iface->state);
		}
		else /* Link is synced -> move endpoint */
		{
			char local[100], remote[100];
			inet_ntop(AF_INET, &iface->ipv4_us, local, sizeof(local));
			inet_ntop(AF_INET, &iface->ipv4_them, remote, sizeof(remote));

			os_exec(
				"/sbin/ifconfig %s tunnel %s %s",
				iface->name, local, remote);
		}
	}

	return true;
}

bool os_int_set_mtu(struct sixxs_interface *iface, unsigned int mtu)
{
	/* Configure the MTU of the interface */
	iface->mtu = mtu;

	if (g_conf->do_sync && iface->state == IFSTATE_UP)
	{
		if (!iface->synced_link)
		{
			/* Set the interface up */
			os_int_set_state(iface, iface->state);
		}
		else
		{
			/* Re-configure the MTU of the interface */
			os_exec(
				"/sbin/ifconfig %s mtu %u",
				iface->name, iface->mtu);
		}
	}

	return true;
}

bool os_int_set_ttl(struct sixxs_interface *iface, unsigned int ttl)
{
	/* Configure the TTL of the interface */
	iface->ttl = ttl;

	/*
	 * NOTE: No TTL support for BSD OS's,
	 * but they are not bothered by the Linux bug anyway
	 */

	return true;
}

/*
 * Given a sockaddr length, round it up to include pad bytes following
 * it.  Assumes the kernel pads to sizeof(long).
 */
#define ROUNDUP(a) ((a) > 0 ? (1 + ((((unsigned int)(a)) - 1) | (sizeof(long) - 1))) : sizeof(long))
  
/*
 * Given a pointer (sockaddr or void *), return the number of bytes
 * taken up by the sockaddr and any padding needed for alignment.
 */
#define SAROUNDUP(X)   ROUNDUP(((struct sockaddr *)(X))->sa_len)

/* Message structure. */
struct message
{
	int key;
	const char *str;
};

/* Routing socket message types. */
struct message rtm_type_str[] =
{
	{RTM_ADD,		"RTM_ADD"},
	{RTM_DELETE,		"RTM_DELETE"},
	{RTM_CHANGE,		"RTM_CHANGE"},
	{RTM_GET,		"RTM_GET"},
	{RTM_LOSING,		"RTM_LOSING"},
	{RTM_REDIRECT,		"RTM_REDIRECT"},
	{RTM_MISS,		"RTM_MISS"},
	{RTM_LOCK,		"RTM_LOCK"},
#ifdef RTM_OLDADD
	{RTM_OLDADD,		"RTM_OLDADD"},
#endif
#ifdef RTM_OLDDEL
	{RTM_OLDDEL,		"RTM_OLDDEL"},
#endif
	{RTM_RESOLVE,		"RTM_RESOLVE"},
	{RTM_NEWADDR,		"RTM_NEWADDR"},
	{RTM_DELADDR,		"RTM_DELADDR"},
	{RTM_IFINFO,		"RTM_IFINFO"},
#ifdef RTM_OIFINFO
	{RTM_OIFINFO,		"RTM_OIFINFO"},
#endif /* RTM_OIFINFO */
#ifdef RTM_NEWMADDR
	{RTM_NEWMADDR,		"RTM_NEWMADDR"},
#endif /* RTM_NEWMADDR */
#ifdef RTM_DELMADDR
	{RTM_DELMADDR,		"RTM_DELMADDR"},
#endif /* RTM_DELMADDR */
#ifdef RTM_IFANNOUNCE
	{RTM_IFANNOUNCE,	"RTM_IFANNOUNCE"},
#endif /* RTM_IFANNOUNCE */
	{0,			NULL}
};

struct message rtm_flag_str[] =
{
	{RTF_UP,		"UP"},
	{RTF_GATEWAY,		"GATEWAY"},
	{RTF_HOST,		"HOST"},
	{RTF_REJECT,		"REJECT"},
	{RTF_DYNAMIC,		"DYNAMIC"},
	{RTF_MODIFIED,		"MODIFIED"},
	{RTF_DONE,		"DONE"},
#ifdef RTF_MASK
	{RTF_MASK,		"MASK"},
#endif /* RTF_MASK */
	{RTF_CLONING,		"CLONING"},
	{RTF_XRESOLVE,		"XRESOLVE"},
	{RTF_LLINFO,		"LLINFO"},
	{RTF_STATIC,		"STATIC"},
	{RTF_BLACKHOLE,		"BLACKHOLE"},
	{RTF_PROTO1,		"PROTO1"},
	{RTF_PROTO2,		"PROTO2"},
#ifdef RTF_PRCLONING
	{RTF_PRCLONING,		"PRCLONING"},
#endif /* RTF_PRCLONING */
#ifdef RTF_WASCLONED
	{RTF_WASCLONED,		"WASCLONED"},
#endif /* RTF_WASCLONED */
#ifdef RTF_PROTO3
	{RTF_PROTO3,		"PROTO3"},
#endif /* RTF_PROTO3 */
#ifdef RTF_PINNED
	{RTF_PINNED,		"PINNED"},
#endif /* RTF_PINNED */
#ifdef RTF_LOCAL
	{RTF_LOCAL,		"LOCAL"},
#endif /* RTF_LOCAL */
#ifdef RTF_BROADCAST
	{RTF_BROADCAST,		"BROADCAST"},
#endif /* RTF_BROADCAST */
#ifdef RTF_MULTICAST
	{RTF_MULTICAST,		"MULTICAST"},
#endif /* RTF_MULTICAST */
	{0,             NULL}
};

/* Message lookup function. */
const char *lookup(struct message *mes, int key);
const char *lookup(struct message *mes, int key)
{
	struct message *pnt;
	
	for (pnt = mes; pnt->str != NULL; pnt++)
	if (pnt->key == key) return pnt->str;
	
	return "";
}

#define af_check(family) ((family) == AF_INET || (family) == AF_INET6)

/* Interface adding function */
void os_update_linkchange(struct if_announcemsghdr *ifan);
void os_update_linkchange(struct if_announcemsghdr *ifan)
{
	struct sixxs_interface *iface;
         
	iface = int_get_by_index(ifan->ifan_index);

	if (ifan->ifan_what == IFAN_ARRIVAL)
	{
		if (iface == NULL)
		{
			if (strcmp("lo0", ifan->ifan_name) == 0)
			{
				mddolog("Found loopback device as index %u\n", ifan->ifan_index);
				g_conf->loopback_ifindex = ifan->ifan_index;
				return;
			}

			iface = int_get_by_name(ifan->ifan_name);
			if (!iface)
			{
				mddolog("Ignoring arrival of non-tunneldevice %s\n", ifan->ifan_name);
				return;
			}

			if (iface->type == IFACE_UNSPEC || iface->state == IFSTATE_DOWN)
			{
				mddolog("%s interface %u/%s, remove it!\n", iface->type == IFACE_UNSPEC ? "Unknown" : "Down-marked", ifan->ifan_index, ifan->ifan_name);

				/* XXX - Ignore certain devices! */

				/* Remove interfaces we don't want to know about */
/*				os_exec("/sbin/ifconfig %s destroy", ifan->ifan_name); */
				os_exec("/sbin/ifconfig %s down", ifan->ifan_name);

				OS_Mutex_Release(&iface->mutex, "netlink_update_link");
				return;
			}
			iface->kernel_ifindex = ifan->ifan_index;
		}

		if_get_flags(iface);

		/* Fixup the MTU if needed */
		if (iface->mtu != if_get_mtu(iface)) os_int_set_mtu(iface, iface->mtu);
    
		mddolog("Interface Arrival: %s index %u\n", iface->name, iface->kernel_ifindex);

		OS_Mutex_Release(&iface->mutex, "os_update_linkchange");
		return;
	}
	else if (ifan->ifan_what == IFAN_DEPARTURE)
	{
		if (iface != NULL)
		{
			mddolog("Received Interface Departure for interface %s/%u/%s\n", iface->name, ifan->ifan_index, ifan->ifan_name);
			/* When the link is gone the rest is desynced too */
			iface->synced_link = false;
			iface->synced_addr = false;
			iface->synced_local = false;
			iface->synced_remote = false;
			iface->synced_subnet = false;
			iface->subnets_up = 0;

			/* BSD changes kernel_ifindex's so zero it out */
			iface->kernel_ifindex = 0;

			OS_Mutex_Release(&iface->mutex, "netlink_update_link");
			return;
		}
		else
		{
			mddolog("Received Interface Departure for unknown interface %u/%s\n", ifan->ifan_index, ifan->ifan_name);
			return;
		}
	}

	/* Unknown IFAN_* message */
	mddolog("os_update_linkchange() called with unknown what %u with interface %p, ifan %u/%s\n", ifan->ifan_what, (void *)iface, ifan->ifan_index, ifan->ifan_name);

	if (iface) OS_Mutex_Release(&iface->mutex, "os_update_linkchange");
	return;
}

/*
 * Handle struct if_msghdr obtained from reading routing socket or
 * sysctl (from interface_list).  There may or may not be sockaddrs
 * present after the header.
 */
void os_update_link(struct if_msghdr *ifm);
void os_update_link(struct if_msghdr *ifm)
{
	struct sixxs_interface	*iface = NULL;
	struct sockaddr_dl	*sdl = NULL;
	unsigned int		i, kernel_mtu = 0;
	char			ifname[IFNAMSIZ];
	unsigned char		*cp;

	ifname[0] = '\0';

	/* paranoia: sanity check structure */
	if (ifm->ifm_msglen < sizeof(struct if_msghdr))
	{
		mdolog(LOG_WARNING, "ifm_read: ifm->ifm_msglen %d too short\n", ifm->ifm_msglen);
		return;
	}

	/*
	 * Check for a sockaddr_dl following the message.  First, point to
	 * where a socakddr might be if one follows the message.
	 */
	cp = (void *)(ifm + 1);

	/*
	 * Check for each sockaddr in turn, advancing over it.  After this
	 * loop, sdl should point to a sockaddr_dl iff one was present.
	 */
	for (i = 1; i != 0; i <<= 1)
	{
		if (i & ifm->ifm_addrs)
		{
			if (i == RTA_IFP)
			{
				sdl = (struct sockaddr_dl *)cp;
				break;
			}

			cp += SAROUNDUP(cp);
		}
	}

	/* Ensure that sdl, if present, is actually a sockaddr_dl. */
	if (sdl != NULL && sdl->sdl_family != AF_LINK)
	{
		mdolog(LOG_ERR, "ifm_read: sockaddr_dl bad AF %d\n", sdl->sdl_family);
		return;
	}

	/*
	 * Look up on ifindex first, because ifindices are the primary
	 * handle for interfaces across the user/kernel boundary.  (Some
	 * messages, such as up/down status changes on NetBSD, do not
	 * include a sockaddr_dl).
	 */
	iface = int_get_by_index(ifm->ifm_index);

	/*
	 * If lookup by index was unsuccessful and we have a name, try
	 * looking up by name.  Interfaces specified in the configuration
	 * file for which the ifindex has not been determined will have
	 * ifindex == -1, and such interfaces are found by this search, and
	 * then their ifindex values can be filled in.
	 */
	if (iface == NULL && sdl != NULL)
	{
		/*
		 * paranoia: sanity check name length.  nlen does not include
		 * trailing zero, but IFNAMSIZ max length does.
		 */
		if (sdl->sdl_nlen >= IFNAMSIZ)
		{
			mdolog(LOG_ERR, "ifm_read: illegal sdl_nlen %d\n", sdl->sdl_nlen);
			return;
		}

		memcpy(ifname, sdl->sdl_data, sdl->sdl_nlen);
		ifname[sdl->sdl_nlen] = '\0';
		iface = int_get_by_name(ifname);
	}

	if (!iface)
	{
		if (strcmp("lo0", ifname) == 0)
		{
			mddolog("Found loopback device as index %u\n", ifm->ifm_index);
			g_conf->loopback_ifindex = ifm->ifm_index;
		}
		else
		{
			mddolog("No interface with ifname %s or index %u\n", ifname, ifm->ifm_index);
		}
		return;
	}

	iface->kernel_ifindex = ifm->ifm_index;
	iface->kernel_flags = ifm->ifm_flags & 0xffffffff;
	if (iface->kernel_flags & IFF_UP) kernel_mtu = if_get_mtu(iface);

	mddolog("Found LINK %s, mtu %u, index %u, %s\n", iface->name, kernel_mtu, iface->kernel_ifindex, iface->kernel_flags & IFF_UP ? "UP" : "DOWN");

	if (iface->type == IFACE_UNSPEC || iface->state == IFSTATE_DOWN)
	{
		if (ifm->ifm_flags & IFF_UP)
		{
			mddolog("%s interface %u/%s, remove it!\n", iface->type == IFACE_UNSPEC ? "Unknown" : "Down-marked", i, iface->name);

			/* XXX - Ignore certain devices! */

			/* Remove interfaces we don't want to know about */
/*			os_exec("/sbin/ifconfig %s destroy", iface->name); */
			os_exec("/sbin/ifconfig %s down", iface->name);
		}
		OS_Mutex_Release(&iface->mutex, "os_update_link");
		return;
	}

	/* Going down */
	if (!(iface->kernel_flags & IFF_UP))
	{
		/* When the link is gone the rest is desynced too */
		iface->synced_link = false;
		iface->synced_addr = false;
		iface->synced_local = false;
		iface->synced_remote = false;
		iface->synced_subnet = false;
		iface->subnets_up = 0;
		OS_Mutex_Release(&iface->mutex, "os_update_link");
		return;
	}

	/* Check tunnel parameters */
	if (iface->type == IFACE_PROTO41 || iface->type == IFACE_PROTO41_HB)
	{
		struct ifreq		ifr;
		int			fd, err;
		struct sockaddr_in	*sa = (struct sockaddr_in *)&ifr.ifr_addr;
		bool			changeendpoint = false;

		fd = socket(AF_INET, SOCK_DGRAM, 0);

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, iface->name, IFNAMSIZ);
		err = ioctl(fd, SIOCGIFPSRCADDR, &ifr);

		if (!err)
		{
			if (sa->sin_family != AF_INET)
			{
				mddolog("LINK %s has protocol %u instead of %u\n", iface->name, sa->sin_family, AF_INET);
			}

			/* Check local tunnel address */
			if (memcmp(&sa->sin_addr, &iface->ipv4_us, sizeof(iface->ipv4_us)) != 0)
			{
				mddolog("LINK %s has local address mismatch\n", iface->name);
				changeendpoint = true;
			}
		}
		else
		{
			mdolog(LOG_ERR, "Could not IOCTL Local Tunnel Information for %s\n", iface->name);
		}

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, iface->name, IFNAMSIZ);
		err = ioctl(fd, SIOCGIFPDSTADDR, &ifr);

		if (!err)
		{
			if (sa->sin_family != AF_INET)
			{
				mddolog("LINK %s has protocol %u instead of %u\n", iface->name, sa->sin_family, AF_INET);
			}

			/* Check local tunnel address */
			if (memcmp(&sa->sin_addr, &iface->ipv4_them, sizeof(iface->ipv4_them)) != 0)
			{
				mddolog("LINK %s has remote address mismatch\n", iface->name);
				changeendpoint = true;
			}
		}
		else
		{
			mdolog(LOG_ERR, "Could not IOCTL Remote Tunnel Information for %s\n", iface->name);
		}
		close(fd);

		if (changeendpoint) os_int_set_endpoint(iface, iface->ipv4_them);
	}

	/* Fixup MTU */
	if (kernel_mtu != iface->mtu)
	{
		os_int_set_mtu(iface, iface->mtu);
	}

	/* The link is synced */
	iface->synced_link = true;

	mddolog("Interface %s's Link is Synced\n", iface->name);

	/* Add interface address */
	os_sync_address_up(iface);

	OS_Mutex_Release(&iface->mutex, "os_update_link");
	return;
}

union sockunion
{
	struct sockaddr		sa;
	struct sockaddr_in	sin;
	struct sockaddr_in6	sin6;
};

void os_ifam_read(struct ifa_msghdr *ifam, struct sockaddr_in6 **addr, unsigned int *mask, struct sockaddr_in6 **dest);
void os_ifam_read(struct ifa_msghdr *ifam, struct sockaddr_in6 **addr, unsigned int *mask, struct sockaddr_in6 **dest)
{
	caddr_t			pnt, end;
	int			len;
	struct sockaddr_in6	*m = NULL, msk;

	pnt = (caddr_t)(ifam + 1);
	end = ((caddr_t)ifam) + ifam->ifam_msglen;

#define IFAMSKIP(r)									\
	if (ifam->ifam_addrs & (r))							\
	{										\
		len = SAROUNDUP(pnt);							\
		pnt += len;								\
	}

#define IFAMGET(x,r)									\
	if (ifam->ifam_addrs & (r) && x != NULL) *x = (struct sockaddr_in6 *)pnt;	\
	IFAMSKIP(r)

	/* We fetch each socket variable into sockunion. */
	IFAMSKIP(RTA_DST);
	IFAMSKIP(RTA_GATEWAY);
	IFAMGET(&m, RTA_NETMASK);
	if (m)
	{
		memset(&msk, 0, sizeof(msk));
		memcpy(&msk, m, len);
		*mask = ip_masklen(&msk.sin6_addr, 128);
	}
	IFAMSKIP(RTA_GENMASK);
	IFAMSKIP(RTA_IFP);
	IFAMGET(addr, RTA_IFA);
	IFAMSKIP(RTA_AUTHOR);
	IFAMGET(dest, RTA_BRD);

	/* Assert read up end point matches to end point */
	if (pnt != end)
	{
		mdolog(LOG_WARNING, "ifam_read() does't read all socket data\n");
	}
}

void os_update_address(struct ifa_msghdr *ifam);
void os_update_address(struct ifa_msghdr *ifam)
{
	struct sixxs_interface	*iface;
	struct sockaddr_in6	*addr = NULL, *gate = NULL;
	char			buf[BUFSIZ];
	unsigned int		dst_len;

	/* Allocate and read address information. */
	os_ifam_read(ifam, &addr, &dst_len, &gate);

	if (!addr)
	{
		mddolog("No address given for interface %u!?\n", ifam->ifam_index);
		return;
	}

	if (addr->sin6_family != AF_INET6)
	{
		mddolog("Ignoring family %u of interface %u\n", addr->sin6_family, ifam->ifam_index);
		return;
	}

	if (IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr))
	{
		inet_ntop(addr->sin6_family, &addr->sin6_addr, buf, sizeof(buf));
		mddolog("Ignoring Link Local Address %s/%u on interface %u\n", buf, dst_len, ifam->ifam_index);
		return;
	}

	/* One of our interfaces? */
	iface = int_get_by_index(ifam->ifam_index); 
	if (iface == NULL)
	{
		inet_ntop(addr->sin6_family, &addr->sin6_addr, buf, sizeof(buf));
		mddolog("No interface for index %d's %s/%u\n", ifam->ifam_index, buf, dst_len);
		return;
	}

	/* Is this address valid on this interface? */
	if (memcmp(&addr->sin6_addr, &iface->ipv6_us, sizeof(iface->ipv6_us)) != 0)
	{
		/*
		 * Don't care when invalids are removed
		 * but remove invalids that are added
		 */
		if (ifam->ifam_type == RTM_NEWADDR)
		{
			/* Remove it */
			inet_ntop(addr->sin6_family, &addr->sin6_addr, buf, sizeof(buf));
			mdolog(LOG_WARNING, "Found invalid address %s/%u on %s, removing it\n",
				buf, dst_len, iface->name);
			os_exec("/sbin/ifconfig %s inet6 %s prefixlen %u -alias",
				iface->name,
				buf,
				dst_len);

			OS_Mutex_Release(&iface->mutex, "os_update_address");
			return;
		}
	}
	else
	{
		if (ifam->ifam_type == RTM_NEWADDR)
		{
			/* If the interface is marked down, remove the address */
			if (iface->synced_link)
			{
				/* Valid address added? -> neat we are synced! */
				iface->synced_addr = true;

				/* Make the route to the remote side */
				os_sync_remote_up(iface);
			}
			else
			{
				/* Remove it */
				inet_ntop(addr->sin6_family, &addr->sin6_addr, buf, sizeof(buf));
				mdolog(LOG_WARNING, "Found valid address %s/%u on %s but it is not UP, removing it\n",
					buf, dst_len, iface->name);
				os_exec("/sbin/ifconfig %s inet6 %s prefixlen %u -alias",
					iface->name,
					buf,
					dst_len);
			}
		}
		else
		{
			/* Only complain when the interface is up */
			if (iface->state == IFSTATE_UP)
			{
				inet_ntop(addr->sin6_family, &addr->sin6_addr, buf, sizeof(buf));
				mdolog(LOG_WARNING, "Noticed removal of valid address %s/%u on %s\n",
					buf, dst_len, iface->name);
			}

			/* Valid address removed? -> desynced */
			iface->synced_addr = false;
		}
	}

	OS_Mutex_Release(&iface->mutex, "os_update_address");
	return;
}

int os_rtm_read(struct rt_msghdr *rtm, struct sockaddr_in6 **dest, unsigned int *mask, struct sockaddr_in6 **gate);
int os_rtm_read(struct rt_msghdr *rtm, struct sockaddr_in6 **dest, unsigned int *mask, struct sockaddr_in6 **gate)
{
	caddr_t			pnt, end;
	struct sockaddr_in6	*m = NULL, msk;
	unsigned int		len;
  
	/* Pnt points out socket data start point. */
	pnt = (caddr_t)(rtm + 1);
	end = ((caddr_t)rtm) + rtm->rtm_msglen;
      
	/* rt_msghdr version check. */
	if (rtm->rtm_version != RTM_VERSION)
	{
		mdolog(LOG_WARNING,
			"Routing message version different %d should be %d."
			"This may cause problems\n", rtm->rtm_version, RTM_VERSION);
	}


#define RTMSKIP(r)									\
	if (rtm->rtm_addrs & (r))							\
	{										\
		len = SAROUNDUP(pnt);							\
		pnt += len;								\
	}

#define RTMGET(x,r)									\
	if (rtm->rtm_addrs & (r) && x != NULL) *x = (struct sockaddr_in6 *)pnt;		\
	RTMSKIP(r)

	/* We fetch each socket variable into sockunion. */
	RTMGET(dest, RTA_DST);
	RTMGET(gate, RTA_GATEWAY);
	RTMGET(&m, RTA_NETMASK);
	if (m)
	{
		memset(&msk, 0, sizeof(msk));
		memcpy(&msk, m, len);
		*mask = ip_masklen(&msk.sin6_addr, 128);
	}
	RTMSKIP(RTA_GENMASK);
	RTMSKIP(RTA_IFP);
	RTMSKIP(RTA_IFA);
	RTMSKIP(RTA_AUTHOR);   
	RTMSKIP(RTA_BRD);

	/* Assert read up to the end of pointer. */
	if (pnt != end)
	{
		mdolog(LOG_WARNING, "os_rtm_read() does't read all socket data\n");
	}

	return rtm->rtm_flags;
}

void os_update_route(struct rt_msghdr *rtm);
void os_update_route(struct rt_msghdr *rtm)
{
	int			flags;
	unsigned int		dst_len, i;
	struct sockaddr_in6	*dest = NULL, *gate = NULL;
	char			dst[100], gw[100];
	struct sixxs_interface	*iface;
	struct sixxs_prefix	*pfx;
	bool			resync = false, rem = false;

	/* Discard self send message. */
	if (rtm->rtm_type != RTM_GET && rtm->rtm_pid == getpid())
	{
		printf("Ignoring %u\n", rtm->rtm_type);
		return;
	}

	/* Read destination and netmask and gateway from rtm message structure. */
	flags = os_rtm_read(rtm, &dest, &dst_len, &gate);

	/* Ignore IPv4 */
	if (dest->sin6_family != AF_INET6) return;

#ifdef RTF_CLONED
	if (flags & RTF_CLONED) return;
#endif
#ifdef RTF_WASCLONED
	if (flags & RTF_WASCLONED) return;
#endif

	if ((rtm->rtm_type == RTM_ADD) && ! (flags & RTF_UP))
	{
		mddolog("os_update_route() Ignoring ADD + DOWN\n");
		return;
	}

	/* This is connected route, thus no gateway */
	if (! (flags & RTF_GATEWAY)) gate = NULL;

	inet_ntop(dest->sin6_family, &dest->sin6_addr, dst, sizeof(dst));
	if (gate) inet_ntop(gate->sin6_family, &gate->sin6_addr, gw, sizeof(gw));

	/* Host routes are always /128's */
	if (flags & RTF_HOST) dst_len = 128;

	mddolog("Received Route: %s/%u%s%s\n", dst, dst_len, gate ? " via " : "", gate ? gw : "");

#if 0
	if (flags & RTF_PROTO1)		SET_FLAG(zebra_flags, ZEBRA_FLAG_SELFROUTE);
	if (flags & RTF_STATIC)		SET_FLAG(zebra_flags, ZEBRA_FLAG_STATIC);
	if (flags & RTF_REJECT)		SET_FLAG(zebra_flags, ZEBRA_FLAG_REJECT);
	if (flags & RTF_BLACKHOLE)	SET_FLAG(zebra_flags, ZEBRA_FLAG_BLACKHOLE);
#endif

	pfx = pfx_get(&dest->sin6_addr, dst_len);
	if (!pfx)
	{
		if (rtm->rtm_type == RTM_ADD || rtm->rtm_type == RTM_GET)
		{
			if (!cfg_pop_prefix_check(&dest->sin6_addr, dst_len))
			{
				mddolog("Ignoring %s/%u which we don't manage\n", dst, dst_len);
			}
			else
			{
				mddolog("Unknown prefix %s/%u, removing it\n", dst, dst_len);
				os_exec("/sbin/route delete %s -prefixlen %u", dst, dst_len);
			}
		}
		return;
	}

	/* Handle PoP prefixes */
	if (pfx->is_popprefix)
	{
		if (rtm->rtm_type == RTM_DELETE) pfx->synced = false;
		else pfx->synced = true;

		OS_Mutex_Release(&pfx->mutex, "os_update_route");
		return;
	}

	i = pfx->interface_id;
	OS_Mutex_Release(&pfx->mutex, "os_update_route");

	iface = int_get(i);
	if (!iface)
	{
		mddolog("Prefix %s/%u doesn't have an associated interface!?\n", dst, dst_len);
		return;
	}

	mddolog("%s IPv6 Route: %s/%u gate %s device %s\n", rtm->rtm_type == RTM_DELETE ? "Delete" : "Add", dst, dst_len, gate ? gw : "::", iface->name);

	if (rtm->rtm_type == RTM_DELETE)
	{
		/* Prefix is removed */
		pfx->synced = false;
		/* One less interface to sync down */
		if (iface->subnets_up > 0) iface->subnets_up--;
		OS_Mutex_Release(&iface->mutex, "os_update_route");
		return;
	}

	/* Check if the interface given is correct
	 * - we know the ifindex already for this interface
	 * - it is not equal to the one we had before
	 * - it is not the loopback
	 * - the new index is not 0
	 * then resync it
	 */
	if (
		iface->kernel_ifindex != 0 &&
		iface->kernel_ifindex != rtm->rtm_index &&
		g_conf->loopback_ifindex != rtm->rtm_index &&
		rtm->rtm_index != 0)
	{
		mddolog("Route %s/%u goes over wrong interface %u instead of %u\n",
			dst, dst_len, rtm->rtm_index, iface->kernel_ifindex);
		resync = true;
	}

	/* Which prefix is it? (local/remote/subnet) */
	if (memcmp(&dest->sin6_addr, &iface->ipv6_us, sizeof(iface->ipv6_us)) == 0)
	{
		/* The link must be synced, otherwise remove it */
		if (!iface->synced_link) rem = true;

		if (!resync && !rem)
		{
			mddolog("Local Route is synced for %s\n", iface->name);
			iface->synced_local = true;
		}
	}
	else if (memcmp(&dest->sin6_addr, &iface->ipv6_them, sizeof(iface->ipv6_them)) == 0)
	{
		/* When the link is not up there is something wrong here */
		if (!iface->synced_link) rem = true;

		/* Check that we are not going over the loopback */
		if (g_conf->loopback_ifindex == rtm->rtm_index)
		{
			/* Need to resync this one then */
			resync = true;
		}

		if (!resync && !rem)
		{
			mddolog("Remote Route is synced for %s\n", iface->name);
			iface->synced_remote = true;

			/* Sync the subnets */
			os_sync_route_up(iface);
		}
	}
	else
	{
		struct sixxs_prefix *subnet;

		rem = true;

		/* Is it a subnet over this tunnel? */
		for (subnet = iface->prefixes; subnet; subnet = subnet->next)
		{
			/* Is it this subnet? */
			if (	subnet->is_tunnel ||
				memcmp(&dest->sin6_addr, &subnet->prefix, sizeof(subnet->prefix)) != 0)
			{
				continue;
			}

			/* Check that we are not going over the loopback */
			if (g_conf->loopback_ifindex == rtm->rtm_index)
			{
				/* Need to resync this one then */
				resync = true;
			}

			/* Make sure that the interface is actually fully working */
                        if (	!iface->synced_link ||
				!iface->synced_addr ||
				!iface->synced_local ||
                        	!iface->synced_remote)
			{
				mddolog("SUBNET %s/%u on %s but link is not fully synced, removing\n", dst, dst_len, iface->name);
				continue;
			}

			/* It's one of ours, keep it */
			rem = false;

			if (!resync)
			{
				/* Mark this one as synced */
				subnet->synced = true;

				mddolog("SUBNET %s/%u on %s\n", dst, dst_len, iface->name);

				/* When all subnets are up, mark it up */
				iface->subnets_up++;
				if (iface->subnets_up == iface->subnets_got) iface->synced_subnet = true;
			}

			break;
		}

		/* When we remove it, it really doesn't belong here, thus don't resync */
		if (rem) resync = false;
	}

	if ((rem || resync) && g_conf->do_sync)
	{
		/* Remove the prefix */
		/* XXX: Might need to specify the correct interface */
		mddolog("Removing %s/%u due to mismatch\n", dst, dst_len);
		os_exec("route delete -inet6 %s -prefixlen %u", dst, dst_len);

		if (resync && iface->state == IFSTATE_UP)
		{
			inet_ntop(AF_INET6, &iface->ipv6_us, gw, sizeof(gw));

			/* Need to bring it up? (effectively reconfiguring it) */
			os_exec("route add -inet6 %s -prefixlen %u %s",
				dst,
				dst_len,
				gw);
		}
	}

	OS_Mutex_Release(&iface->mutex, "os_update_route");
	return;
}

int os_socket(void);
int os_socket(void)
{
	int	ret, sock;

	sock = socket(AF_ROUTE, SOCK_RAW, 0);
	if (sock < 0)
	{
		char buf[256];
		memset(buf, 0, sizeof(buf));
		strerror_r(errno, buf, sizeof(buf));
		mdolog(LOG_ERR, "Can't open kernel socket: %s (%d)\n", buf, errno);
		return -1;
	}

	ret = fcntl(sock, F_SETFL, O_NONBLOCK);
	if (ret < 0)
	{
		char buf[256];
		memset(buf, 0, sizeof(buf));
		strerror_r(errno, buf, sizeof(buf));
		mdolog(LOG_ERR, "Can't set kernel socket flags: %s (%d)\n", buf, errno);
		close(sock);
		return -1;
	}

	socket_setblock(sock);

	return sock;
}

/* Kernel routing table read up by sysctl function. */
void os_read_routes(void);
void os_read_routes(void)
{
	caddr_t			buf, end, ref;
	size_t			bufsiz;
	struct rt_msghdr	*rtm;
	unsigned int		i = 0;

	int mib[] = { CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP, 0 };

	mddolog("OS Handler: BSD - Fetching Routes\n");

	/* Get buffer size. */
	if (sysctl(mib, sizeof(mib)/sizeof(mib[0]), NULL, &bufsiz, NULL, 0) < 0)
	{
		char buf2[128];
		memset(buf2, 0, sizeof(buf2));
		strerror_r(errno, buf2, sizeof(buf2));
		mdolog(LOG_WARNING, "sysctl(CTL_NET,PF_ROUTE,NET_RT_DUMP) size failed: %s (%d)", buf2, errno);
		return;
	}

	/* Allocate buffer. */
	ref = buf = malloc(bufsiz);
	if (!ref)
	{
		mdolog(LOG_ERR, "Couldn't allocate memory for sysctl routing table dump\n");
		return;
	}

	mddolog("Getting %u bytes of routing tables\n", bufsiz);

	/* Read routing table information by calling sysctl(). */
	if (sysctl(mib, sizeof(mib)/sizeof(mib[0]), buf, &bufsiz, NULL, 0) < 0)
	{
		char buf2[128];
		memset(buf2, 0, sizeof(buf2));
		strerror_r(errno, buf2, sizeof(buf2));
		mdolog(LOG_WARNING, "sysctl(CTL_NET,PF_ROUTE,NET_RT_DUMP) fetch failed: %s (%d)", buf2, errno);
		return;
	}

	for (end = buf + bufsiz; buf < end; buf += rtm->rtm_msglen)
	{
		rtm = (struct rt_msghdr *)buf;
		os_update_route(rtm);
		i++;
	}

	/* Free buffer. */
	free(ref);

	mddolog("OS Handler: BSD - Fetching Routes (done)\n");
}

/* Interface listing up function using sysctl(). */
void os_read_interfaces(void);
void os_read_interfaces(void)
{
	caddr_t			ref, buf, end;
	size_t			bufsiz;
	struct if_msghdr	*ifm;

	int mib[] = { CTL_NET, PF_ROUTE, 0, 0, /*  AF_INET & AF_INET6 */ NET_RT_IFLIST, 0 };

	mddolog("OS Handler: BSD - Fetching Interfaces\n");

	/* Query buffer size. */
	if (sysctl(mib, sizeof(mib)/sizeof(mib[0]), NULL, &bufsiz, NULL, 0) < 0)
	{
		char buf2[128];
		memset(buf2, 0, sizeof(buf2));
		strerror_r(errno, buf2, sizeof(buf2));
		mdolog(LOG_WARNING, "sysctl() error by %s (%d)\n", buf2, errno);
		return;
	}

	/* We free this memory at the end of this function. */
	ref = buf = malloc(bufsiz);

	/* Fetch interface informations into allocated buffer. */
	if (sysctl(mib, sizeof(mib)/sizeof(mib[0]), buf, &bufsiz, NULL, 0) < 0)
	{
		char buf2[128];
		memset(buf2, 0, sizeof(buf2));
		strerror_r(errno, buf2, sizeof(buf2));
		mdolog(LOG_WARNING, "sysctl error by %s (%d)\n", buf2, errno);
		return;
	}

	/* Parse both interfaces and addresses. */
	for (end = buf + bufsiz; buf < end; buf += ifm->ifm_msglen)
	{
		ifm = (struct if_msghdr *)buf;

		switch (ifm->ifm_type)
		{
		case RTM_IFINFO:
			os_update_link(ifm);
			break;

		case RTM_NEWADDR:
			os_update_address((struct ifa_msghdr *)ifm);
			break;

		default:
			mdolog(LOG_WARNING, "interfaces_list(): unexpected message type %u\n", ifm->ifm_type);
			break;
		}
	}

	/* Free sysctl buffer. */
	free(ref);

	mddolog("OS Handler: BSD - Fetching Interfaces (done)\n");
}



/* Public functions */
bool os_sync_complete(void)
{
	if (!os_initialized)
	{
		mdolog(LOG_ERR, "os_sync_complete() - Not initialized yet!\n");
		return false;
	}

	os_read_interfaces();
	os_read_routes();

	return true;
}

#ifndef RTAX_MAX
#ifdef RTA_NUMBITS
#define RTAX_MAX	RTA_NUMBITS
#else
#define RTAX_MAX	8
#endif
#endif

void *os_dthread(void UNUSED *arg);
void *os_dthread(void UNUSED *arg)
{
	struct rt_msghdr	*rtm;
	int			n;
	fd_set			readset;
	struct timeval		timeout;

	union
	{  
		/* Routing information. */
		struct
		{
			struct rt_msghdr rtm;
			struct sockaddr_storage addr[RTAX_MAX];
		} r;

		/* Interface information. */
		struct
		{
			struct if_msghdr ifam;
			struct sockaddr_storage addr[RTAX_MAX];
		} im;

		/* Interface address information. */
		struct
		{
			struct ifa_msghdr ifa;
			struct sockaddr_storage addr[RTAX_MAX];
		} ia;

		/* Interface arrival/departure */
		struct
		{
			struct if_announcemsghdr ifan;
			struct sockaddr_storage addr[RTAX_MAX];
		} ian;
	} buf;

	/* Show that we have started */
	mdolog(LOG_INFO, "OS Handler: BSD - started\n");

	while (g_conf->running)
	{
		/* Timeout after 5 seconds non-activity to check if we are still running */
		FD_ZERO(&readset);
		FD_SET(os_kernelsocket, &readset);
		memset(&timeout, 0, sizeof(timeout));
		timeout.tv_sec = 5;
		n = select(os_kernelsocket+1, &readset, NULL, NULL, &timeout);

		/* Nothing happened (timeout) */
		if (n == 0) continue;

		if (n > 0) n = read(os_kernelsocket, &buf, sizeof(buf));
		if (n < 0 && errno != EWOULDBLOCK && errno != EAGAIN)
		{
			char buf2[128];
			memset(buf2,0,sizeof(buf2));
			strerror_r(errno, buf2, sizeof(buf2));
			mdolog(LOG_ERR, "kernel socket error: %s (%d)\n", buf2, errno);
			break;
		}

		rtm = &buf.r.rtm;

		if (g_conf->verbose > 5)
		{
			const char	*type = "Unknown";
			struct message	*mes;
			char		flags[BUFSIZ];

			type = lookup(rtm_type_str, rtm->rtm_type);

			mddolog("Kernel: Len: %d Type: %s\n", rtm->rtm_msglen, type);

			flags[0] = '\0';
			for (mes = rtm_flag_str; mes->key != 0; mes++)
			{
				if (mes->key & rtm->rtm_flags)
				{
					strlcat(flags, mes->str, sizeof(flags));
					strlcat(flags, " ", sizeof(flags));
				}
			}
			mddolog("Kernel: flags %s\n", flags);

			mddolog("Kernel: message seq %d\n", rtm->rtm_seq);
			mddolog("Kernel: pid %d\n", rtm->rtm_pid);
		}

		/* XXX - might want to substract the msg_len from n and read further, appending to it */
		if (rtm->rtm_msglen != n)
		{
			mdolog(LOG_WARNING, "kernel socket: rtm->rtm_msglen %d, nbytes %d, type %d\n",
				rtm->rtm_msglen, n, rtm->rtm_type);
			break;
		}

		switch (rtm->rtm_type)
		{
		case RTM_ADD:
		case RTM_DELETE:
			os_update_route(rtm);
			break;

		case RTM_IFINFO:
			os_update_link(&buf.im.ifam);
			break;

		case RTM_NEWADDR:
		case RTM_DELADDR:
			os_update_address(&buf.ia.ifa);
			break;

		case RTM_IFANNOUNCE:
			os_update_linkchange(&buf.ian.ifan);
			break;

#ifdef RTM_NEWMADDR
		case RTM_NEWMADDR:
			/* Silently ignore */
			break;
#endif

		default:
			mddolog("Unprocessed RTM_type: %s (%d)\n", lookup(rtm_type_str, rtm->rtm_type), rtm->rtm_type);
			break;
		}
	}

	mdolog(LOG_INFO, "OS Handler: BSD - exiting\n");

	return NULL;
}

/* Initialize OS Handler, might start a thread */
bool os_init(void)
{
	/* Don't init twice */
	if (os_initialized) return true;

	/* We are done */
	os_initialized = true;

	/* Set sysconf stuff making sure this is set ;) */
	os_exec("sysctl -q -w net.inet6.ip6.forwarding=1");

	/* XXX - Some PoPs might use RA to configure themselves :( */
	/*
	os_exec("sysctl -q -w net.inet6.ip6.accept_rtadv=0");
	*/

	/* Build the sockets */
	os_kernelsocket = os_socket();

	/* Find out where lo0 hangs out at */
	g_conf->loopback_ifindex = if_get_ifindex_byname("lo0");

	/*
	 * Create a thread for handling updates from the OS
	 * Our own changes (using the cmd channel) will also be seen here)
	 */
	thread_add("OS", os_dthread, NULL, true);

	return true;
}

