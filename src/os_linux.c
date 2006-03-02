/**************************************
 SixXSd - SixXS PoP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
***************************************
 $Author: jeroen $
 $Id: os_linux.c,v 1.21 2006-03-02 12:13:02 jeroen Exp $
 $Date: 2006-03-02 12:13:02 $

 SixXSd - Linux specific code
**************************************/

#include "sixxsd.h"

const char module_os[] = "os_linux";
#define module module_os

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_tunnel.h>

/* Socket interface to kernel */
struct nlsock
{
	int sock;
	int seq;
	struct sockaddr_nl snl;
	const char *name;
};

struct nlsock os_netlink, os_netlink_cmd;

bool os_initialized = false;

/* OS Helper functions */
void os_exec(const char *fmt, ...);
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

		inet_ntop(AF_INET, &g_conf->pop_ipv4, ipv4_us, sizeof(ipv4_us));
		inet_ntop(AF_INET, &iface->ipv4_them, ipv4_them, sizeof(ipv4_them));

		os_exec(
			"ip tunnel add %s mode sit local %s remote %s ttl %u",
			iface->name,
			ipv4_us,
			ipv4_them,
			iface->ttl);
	}
	else if (iface->type == IFACE_AYIYA)
	{
		if (!ayiya_start(iface)) return false;
	}

	/* Mark the interface up + set MTU */
	os_exec(
		"ip link set mtu %u up dev %s",
		iface->mtu,
		iface->name);

	if (iface->type == IFACE_AYIYA)
	{
		char ipv6_ll[100];

		/* tun interfaces don't come with a LinkLocal address so create one */
		inet_ntop(AF_INET6, &iface->ipv6_ll, ipv6_ll, sizeof(ipv6_ll));
		os_exec(
			"ip -6 addr add %s/%u dev %s",
			ipv6_ll,
			64,
			iface->name);
	}

	return true;
}

/* Mark interface down */
bool os_sync_link_down(struct sixxs_interface *iface);
bool os_sync_link_down(struct sixxs_interface *iface)
{
	/* Only when syncing */
	if (g_conf->do_sync && iface->synced_link)
	{
		os_exec(
			"ip link set %s down",
			iface->name);

		if (	iface->type == IFACE_PROTO41 ||
			iface->type == IFACE_PROTO41_HB)
		{
			os_exec(
				"ip tunnel del %s",
				iface->name);
		}
		else if (iface->type == IFACE_AYIYA)
		{
			ayiya_stop(iface);
		}

		iface->synced_link = false;
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
			"ip -6 addr add %s/%u dev %s",
			addr,
			/* we only route /128 tunnels */
			128,
			iface->name);
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
			"ip -6 addr del %s/%u dev %s",
			addr,
			128,
			iface->name);

		iface->synced_addr = false;
		iface->synced_local = false;
	}

	return true;
}

bool os_sync_remote_up(struct sixxs_interface *iface);
bool os_sync_remote_up(struct sixxs_interface *iface)
{
	char them[100];

	/* Only when syncing */
	if (g_conf->do_sync && !iface->synced_remote)
	{
		inet_ntop(AF_INET6, &iface->ipv6_them, them, sizeof(them));
		os_exec(
			"ip -6 ro add %s/%u dev %s",
			them,
			/* we only route /128 tunnels */
			128,
			iface->name);
	}

	return true;
}

bool os_sync_route_up(struct sixxs_interface *iface);
bool os_sync_route_up(struct sixxs_interface *iface)
{
	char			them[100], subnet[100];
	struct sixxs_prefix	*pfx;

	/* Only when syncing */
	if (g_conf->do_sync && !iface->synced_subnet)
	{
		inet_ntop(AF_INET6, &iface->ipv6_them, them, sizeof(them));

		/* Sync subnets over this tunnel */
		for (pfx = iface->prefixes; pfx; pfx = pfx->next)
		{
			if (pfx->is_tunnel) continue;

			inet_ntop(AF_INET6, &pfx->prefix, subnet, sizeof(subnet));
			os_exec(
				"ip -6 ro add %s/%u via %s dev %s",
				subnet,
				pfx->length,
				them,
				iface->name);
		}
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
			"ip -6 ro del %s/%u via %s dev %s",
			subnet,
			pfx->length,
			them,
			iface->name);
	}
	iface->synced_subnet = false;
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
			"ip -6 ro del %s/%u dev %s",
			them,
			/* we only route /128 tunnels */
			128,
			iface->name);

		iface->synced_remote = false;
	}
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
			inet_ntop(AF_INET, &g_conf->pop_ipv4, local, sizeof(local));
			inet_ntop(AF_INET, &iface->ipv4_them, remote, sizeof(remote));

			os_exec(
				"ip tunnel change %s local %s remote %s",
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
				"ip link set mtu %u dev %s",
				iface->mtu, iface->name);
		}
	}

	return true;
}

bool os_int_set_ttl(struct sixxs_interface *iface, unsigned int ttl)
{
	/* Configure the TTL of the interface */
	iface->ttl = ttl;

	if (g_conf->do_sync && iface->state == IFSTATE_UP)
	{
		if (!iface->synced_link)
		{
			/* Set the interface up */
			os_int_set_state(iface, iface->state);
		}
		else
		{
			/* Re-configure the TTL of the interface */
			os_exec(
				"ip tunnel change %s ttl %u",
				iface->name, ttl);
		}
	}

	return true;
}

/* Message structure. */
struct message
{
	int key;
	const char *str;
};

struct message nlmsg_str[] = {
	{RTM_NEWROUTE,	"RTM_NEWROUTE"},
	{RTM_DELROUTE,	"RTM_DELROUTE"},
	{RTM_GETROUTE,	"RTM_GETROUTE"},
	{RTM_NEWLINK,	"RTM_NEWLINK"},
	{RTM_DELLINK,	"RTM_DELLINK"},
	{RTM_GETLINK,	"RTM_GETLINK"},
	{RTM_NEWADDR,	"RTM_NEWADDR"},
	{RTM_DELADDR,	"RTM_DELADDR"},
	{RTM_GETADDR,	"RTM_GETADDR"},
	{0, NULL}
};

struct message rtn_types[] = {
	{RTN_UNICAST,		"Unicast"},
	{RTN_LOCAL,		"Local"},
	{RTN_BROADCAST,		"Broadcast"},
	{RTN_ANYCAST,		"Anycast"},
	{RTN_MULTICAST,		"Multicast"},
	{RTN_BLACKHOLE,		"Blackhole"},
	{RTN_UNREACHABLE,	"Unreachable"},
	{RTN_PROHIBIT,		"Administratively prohibited"},
	{RTN_THROW,		"Not in this table"},
	{RTN_NAT,		"Translate this address"},
	{RTN_XRESOLVE,		"External"},
	{RTN_UNSPEC,		"Unspec"},
	{0, NULL},
};

#ifndef ARPHRD_HWX25
#define ARPHRD_HWX25 ARPHDR_HWX25
#endif

#ifndef ARPHRD_TUNTAP
#define ARPHRD_TUNTAP 65534
#endif

struct message ifi_types[] = {
	{ARPHRD_NETROM,		"From KA9Q: NET/ROM pseudo"},
	{ARPHRD_ETHER,		"Ethernet 10/100Mbps"},
	{ARPHRD_EETHER,		"Experimental Ethernet"},
	{ARPHRD_AX25,		"AX.25 Level 2"},
	{ARPHRD_PRONET,		"PROnet token ring"},
	{ARPHRD_CHAOS,		"Chaosnet"},
	{ARPHRD_IEEE802,	"IEEE 802.2 Ethernet/TR/TB"},
	{ARPHRD_ARCNET,		"ARCnet"},
	{ARPHRD_APPLETLK,	"APPLEtalk"},
	{ARPHRD_DLCI,		"Frame Relay DLCI"},
	{ARPHRD_ATM,		"ATM"},
	{ARPHRD_METRICOM,	"Metricom STRIP (new IANA id)"},
	{ARPHRD_IEEE1394,	"Firewire IEEE 1394 IPv4 - RFC 2734"},
	{ARPHRD_EUI64,		"EUI-64"},
	{ARPHRD_INFINIBAND,	"InfiniBand"},
	{ARPHRD_SLIP,		"SLIP"},
	{ARPHRD_CSLIP,		"CSLIP"},
	{ARPHRD_SLIP6,		"SLIP6"},
	{ARPHRD_CSLIP6,		"CSLIP6"},
	{ARPHRD_RSRVD,		"Reserved / Notional KISS type"},
	{ARPHRD_ADAPT,		"ADAPT"},
	{ARPHRD_ROSE,		"ROSE"},
	{ARPHRD_X25,		"CCITT X.25"},
	{ARPHRD_HWX25,		"Boards with X.25 in firmware"},
	{ARPHRD_PPP,		"PPP"},
	{ARPHRD_CISCO,		"Cisco HDLC"},
	{ARPHRD_LAPB,		"LAPB"},
	{ARPHRD_DDCMP,		"Digital's DDCMP"},
	{ARPHRD_RAWHDLC,	"Raw HDLC"},
	{ARPHRD_TUNNEL,		"IPIP tunnel"},
	{ARPHRD_TUNNEL6,	"IPIP6 tunnel"},
	{ARPHRD_FRAD,		"Frame Relay Access Device"},
	{ARPHRD_SKIP,		"SKIP vif"},
	{ARPHRD_LOOPBACK,	"Loopback device"},
	{ARPHRD_LOCALTLK,	"Localtalk device"},
	{ARPHRD_FDDI,		"Fiber Distributed Data Interface."},
	{ARPHRD_BIF,		"AP1000 BIF"},
	{ARPHRD_SIT,		"SIT / proto-41 / IPv6-in-IPv4"},
	{ARPHRD_IPDDP,		"IP-in-DDP tunnel"},
	{ARPHRD_IPGRE,		"GRE over IP"},
	{ARPHRD_PIMREG,		"PIMSM register interface"},
	{ARPHRD_HIPPI,		"High Performance Parallel I'face"},
	{ARPHRD_ASH,		"(Nexus Electronics) Ash"},
	{ARPHRD_ECONET,		"Acorn Econet"},
	{ARPHRD_IRDA,		"Linux-IrDA"},
	{ARPHRD_FCPP,		"Point to point fibrechanel"},
	{ARPHRD_FCAL,		"Fibrechanel arbitrated loop"},
	{ARPHRD_FCPL,		"Fibrechanel public loop"},
	{ARPHRD_FCFABRIC,	"Fibrechanel fabric"},
	{ARPHRD_IEEE802_TR,	"Magic type ident for TR"},
	{ARPHRD_IEEE80211,	"IEEE 802.11"},
	{ARPHRD_TUNTAP,		"Tun/Tap - Generic Encapsulation Device"},
	{0, NULL},
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

/* Utility function for parse rtattr. */
void netlink_parse_rtattr(struct rtattr **tb, int max, struct rtattr *rta, int len);
void netlink_parse_rtattr(struct rtattr **tb, int max, struct rtattr *rta, int len)
{
	while (RTA_OK(rta, len))
	{
		if (rta->rta_type <= max) tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta, len);
	}
}

void netlink_update_link(struct nlmsghdr *h);
void netlink_update_link(struct nlmsghdr *h)
{
	int			len, i;
	struct ifinfomsg	*ifi;
	struct rtattr		*tb[IFLA_MAX + 1];
	struct sixxs_interface	*iface;
	char			*name;
	unsigned int		kernel_mtu;

	ifi = NLMSG_DATA(h);

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
	if (len < 0) return;

	/* Looking up interface name. */
	memset(tb, 0, sizeof(tb));
	netlink_parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);

	if (tb[IFLA_IFNAME] == NULL)
	{
		mddolog("Ignoring device without a name, ifindex %u!\n", ifi->ifi_index);
		return;
	}
	name = (char *)RTA_DATA(tb[IFLA_IFNAME]);

	if (strncmp(g_conf->pop_tunneldevice, name, strlen(g_conf->pop_tunneldevice)) != 0)
	{
		if (strcmp("lo", name) == 0)
		{
			mddolog("Found loopback device as index %u\n", ifi->ifi_index);
			g_conf->loopback_ifindex = ifi->ifi_index;
		}
		else
		{
			mddolog("Ignoring non-tunneldevice %s\n", name);
		}
		return;
	}

	/* Shortcut to get the interface */
	i = atoi(&name[strlen(g_conf->pop_tunneldevice)]);
	iface = int_get(i);

	if (!iface || iface->type == IFACE_UNSPEC || iface->state == IFSTATE_DOWN)
	{
		if (h->nlmsg_type == RTM_NEWLINK && (ifi->ifi_flags & IFF_UP))
		{
			
			/* XXX - Remove interfaces we don't want to know about */
			mddolog("%s interface %u/%s, remove it!\n", !iface || iface->type == IFACE_UNSPEC ? "Unknown" : "Down-marked", i, name);

			/* XXX - Ignore certain devices! */

			/* Removing SIT tunnels is easy, do it directly */
			if (ifi->ifi_type == ARPHRD_SIT)
			{
				/* When the link is gone the rest is desynced too */
				iface->synced_link = false;
				iface->synced_addr = false;
				iface->synced_local = false;
				iface->synced_remote = false;
				iface->synced_subnet = false;

				/* Remove the interface */
				os_exec("ip tunnel del %s", name);
			}
		}
		if (iface) OS_Mutex_Release(&iface->mutex, "netlink_update_link");
		return;
	}

	iface->kernel_ifindex = ifi->ifi_index;
	iface->kernel_flags = ifi->ifi_flags & 0xffffffff;
	kernel_mtu = *(int *)RTA_DATA(tb[IFLA_MTU]);

	mddolog("Found LINK %s, type %u (%s), mtu %u, %s\n", name, ifi->ifi_type, lookup(ifi_types, ifi->ifi_type), kernel_mtu, iface->kernel_flags && IFF_UP ? "UP" : "DOWN");

	/* Going down */
	if (!(iface->kernel_flags && IFF_UP))
	{
		/* When the link is gone the rest is desynced too */
		iface->synced_link = false;
		iface->synced_addr = false;
		iface->synced_local = false;
		iface->synced_remote = false;
		iface->synced_subnet = false;
		OS_Mutex_Release(&iface->mutex, "netlink_update_link");
		return;
	}

	/* Protocol-41 = SIT, AYIYA = tun/tap */
	if (	(	(iface->type == IFACE_PROTO41 || iface->type == IFACE_PROTO41_HB) &&
			ifi->ifi_type == ARPHRD_SIT) ||
		(	iface->type == IFACE_AYIYA &&
			ifi->ifi_type == ARPHRD_TUNTAP))
	{
		/* Check tunnel parameters */
		if (iface->type == IFACE_PROTO41 || iface->type == IFACE_PROTO41_HB)
		{
			struct ifreq		ifr;
			struct ip_tunnel_parm	p;
			int			fd, err;

			memset(&p, 0, sizeof(p));
			strncpy(ifr.ifr_name, name, IFNAMSIZ);
			ifr.ifr_ifru.ifru_data = (void *)&p;
			fd = socket(AF_INET, SOCK_DGRAM, 0);
			err = ioctl(fd, SIOCGETTUNNEL, &ifr);
			close(fd);

			if (!err)
			{
				if (p.iph.protocol != IPPROTO_IPV6)
				{
					mddolog("LINK %s has protocol %u instead of %u\n", name, p.iph.protocol, IPPROTO_IPV6);
				}

				/* local & remote tunnel addresses */
				if (	!p.iph.saddr || memcmp(&p.iph.saddr, &g_conf->pop_ipv4, sizeof(g_conf->pop_ipv4)) != 0 ||
					!p.iph.daddr || memcmp(&p.iph.daddr, &iface->ipv4_them, sizeof(iface->ipv4_them)) != 0)
				{
					mddolog("LINK %s has local/remote address mismatch\n", name);
					os_int_set_endpoint(iface, iface->ipv4_them);
				}

				if (p.iph.ttl != iface->ttl)
				{
					mddolog("LINK %s currently has a TTL of %u instead of %u\n", name, p.iph.ttl, iface->ttl);
					os_int_set_ttl(iface, iface->ttl);
				}
			}
			else
			{
				mdolog(LOG_ERR, "Could not IOCTL Tunnel Information for %s\n", name);
			}
		}

		/* Fixup MTU */
		if (kernel_mtu != iface->mtu)
		{
			os_int_set_mtu(iface, iface->mtu);
		}

		/* When the link was not synced yet try to give it an address */
		if (!iface->synced_link)
		{
			iface->synced_link = true;

			/* Add interface address */
			os_sync_address_up(iface);
		}
	}
	else
	{
		mddolog("Link type %u of %s doesn't match expected link type\n", ifi->ifi_type, name);
		/* When the link is gone the rest is desynced too */
		iface->synced_link = false;
		iface->synced_addr = false;
		iface->synced_local = false;
		iface->synced_remote = false;
		iface->synced_subnet = false;

		/* XXX Try to delete the old one */
	}

	OS_Mutex_Release(&iface->mutex, "netlink_update_link");
	return;
}

void netlink_update_address(struct nlmsghdr *h);
void netlink_update_address(struct nlmsghdr *h)
{
	struct ifaddrmsg	*ifa;
	struct rtattr		*tb[IFA_MAX + 1];
	int			len;
	struct sixxs_interface	*iface;
	void			*addr;
	char			buf[BUFSIZ];

	ifa = NLMSG_DATA(h);
	if (ifa->ifa_family != AF_INET && ifa->ifa_family != AF_INET6)
	{
		mddolog("Ignoring family %u\n", ifa->ifa_family);
		return;
	}

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifaddrmsg));

	memset(tb, 0, sizeof(tb));
	netlink_parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa), len);

	if (tb[IFA_ADDRESS] != NULL && IN6_IS_ADDR_LINKLOCAL(RTA_DATA(tb[IFA_ADDRESS])))
	{
		inet_ntop(ifa->ifa_family, RTA_DATA(tb[IFA_ADDRESS]), buf, sizeof(buf));
		mddolog("Ignoring Link Local Address %s on interface %u\n", buf, ifa->ifa_index);
		return;
	}

	iface = int_get_by_index(ifa->ifa_index);
	if (1)
	{
		mddolog("netlink_interface_addr %s %s:\n", lookup(nlmsg_str, h->nlmsg_type), iface ? iface->name : "unknown");

		if (tb[IFA_LOCAL])
		{
			inet_ntop(ifa->ifa_family, RTA_DATA(tb[IFA_LOCAL]), buf, sizeof(buf));
			mddolog("  IFA_LOCAL     %s/%d\n", buf, ifa->ifa_prefixlen);
		}

		if (tb[IFA_ADDRESS])
		{
			inet_ntop(ifa->ifa_family, RTA_DATA(tb[IFA_ADDRESS]), buf, sizeof(buf));
			mddolog("  IFA_ADDRESS   %s/%d\n", buf, ifa->ifa_prefixlen);
		}

		if (tb[IFA_BROADCAST])
		{
			inet_ntop(ifa->ifa_family, RTA_DATA(tb[IFA_BROADCAST]), buf, sizeof(buf));
			mddolog("  IFA_BROADCAST %s/%d\n", buf, ifa->ifa_prefixlen);
		}

		if (tb[IFA_LABEL])
		{
			mddolog("  IFA_LABEL     %s\n", (char *)RTA_DATA(tb[IFA_LABEL]));
		}
	}

	if (!iface)
	{
		mddolog("Unknown interface %u\n", ifa->ifa_index);
		return;
	}

	if (ifa->ifa_family == AF_INET)
	{
		mddolog("We don't care (much) about IPv4 addresses\n");
		OS_Mutex_Release(&iface->mutex, "netlink_update_address");
		return;
	}

	if (tb[IFA_ADDRESS] == NULL) tb[IFA_ADDRESS] = tb[IFA_LOCAL];
	addr = RTA_DATA(tb[IFA_ADDRESS]);

	/* Is this address valid on this interface? */
	if (memcmp(addr, &iface->ipv6_us, sizeof(iface->ipv6_us)) != 0)
	{
		/*
		 * Don't care when invalids are removed
		 * but remove invalids that are added
		 */
		if (h->nlmsg_type == RTM_NEWADDR)
		{
			/* Remove it */
			inet_ntop(ifa->ifa_family, addr, buf, sizeof(buf));
			mdolog(LOG_WARNING, "Found invalid address %s/%u on %s, removing it\n",
				buf, ifa->ifa_prefixlen, iface->name);
			os_exec("ip -6 addr del %s/%u dev %s",
				buf, ifa->ifa_prefixlen, iface->name);

			OS_Mutex_Release(&iface->mutex, "netlink_update_address");
			return;
		}
	}
	else
	{
		if (h->nlmsg_type == RTM_NEWADDR)
		{
			/* Valid address added? -> neat we are synced! */
			iface->synced_addr = true;

			/* Make the route to the remote side */
			os_sync_remote_up(iface);
		}
		else
		{
			/* Only complain when the interface is up */
			if (iface->state == IFSTATE_UP)
			{
				inet_ntop(ifa->ifa_family, addr, buf, sizeof(buf));
				mdolog(LOG_WARNING, "Noticed removal of valid address %s/%u on %s\n",
					buf, ifa->ifa_prefixlen, iface->name);
			}

			/* Valid address removed? -> desynced */
			iface->synced_addr = false;
		}
	}

	OS_Mutex_Release(&iface->mutex, "netlink_update_address");

	return;
}

void netlink_update_route(struct nlmsghdr *h);
void netlink_update_route(struct nlmsghdr *h)
{
	int			len;
	unsigned int		idx = 0, i;
	struct rtmsg		*rtm;
	struct rtattr		*tb[RTA_MAX + 1];
	char			anyaddr[16] = { 0 };
	void			*dest = NULL, *gate = NULL;
	char			dst[100], gw[100];
	struct sixxs_interface	*iface;
	struct sixxs_prefix	*pfx;
	bool			resync = false, rem = false;

	rtm = NLMSG_DATA(h);

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg));
	if (len < 0)
	{
		mdolog(LOG_ERR, "Message too short %d\n", len);
		return;
	}

	memset(tb, 0, sizeof tb);
	netlink_parse_rtattr(tb, RTA_MAX, RTM_RTA(rtm), len);

	/*
	 * Ignore cloned, redirected and non-IPv6 routes
	 * cloning happens a lot when pinging for instance...
	 */
	if (	rtm->rtm_flags & RTM_F_CLONED ||
		rtm->rtm_flags & RTPROT_REDIRECT ||
		rtm->rtm_family != AF_INET6)
	{
		return;
	}

	if (tb[RTA_OIF]) idx = *(int *)RTA_DATA(tb[RTA_OIF]);
	else idx = 0;

	if (tb[RTA_DST]) dest = RTA_DATA(tb[RTA_DST]);
	else dest = anyaddr;

	/* Multipath treatment is needed. */
	if (tb[RTA_GATEWAY]) gate = RTA_DATA(tb[RTA_GATEWAY]);

	inet_ntop(rtm->rtm_family, dest, dst, sizeof(dst));
	if (gate) inet_ntop(rtm->rtm_family, gate, gw, sizeof(gw));

	pfx = pfx_get(dest, rtm->rtm_dst_len);
	if (!pfx)
	{
		if (!cfg_pop_prefix_check(dest, rtm->rtm_dst_len))
		{
			mddolog("Ignoring %s/%u which we don't manage\n", dst, rtm->rtm_dst_len);
		}
		else
		{
			mddolog("Unknown prefix %s/%u, removing it\n", dst, rtm->rtm_dst_len);
			os_exec("ip -6 ro del %s/%u", dst, rtm->rtm_dst_len);
		}
		return;
	}

	/* Handle PoP prefixes */
	if (pfx->is_popprefix)
	{
		if (h->nlmsg_type == RTM_DELROUTE) pfx->synced = false;
		else pfx->synced = true;

		OS_Mutex_Release(&pfx->mutex, "netlink_update_route");
		return;
	}

	i = pfx->interface_id;
	OS_Mutex_Release(&pfx->mutex, "netlink_update_route");

	iface = int_get(i);
	if (!iface)
	{
		mddolog("Prefix %s/%u doesn't have an associated interface!?\n", dst, rtm->rtm_dst_len);
		return;
	}

	mddolog("IPv6 Route: %s/%u gate %s device %s (%u:%s)\n", dst, rtm->rtm_dst_len, gate ? gw : "::", iface->name, rtm->rtm_type, lookup(rtn_types, rtm->rtm_type));

	if (h->nlmsg_type == RTM_DELROUTE)
	{
		/* Don't care about Route Deletion */
		OS_Mutex_Release(&iface->mutex, "netlink_update_route");
		return;
	}

	/* Route should go over either the interface or the loopback */
	/* XXX: Only local routes should go over loopback! */
	if (iface->kernel_ifindex != 0 && iface->kernel_ifindex != idx && g_conf->loopback_ifindex != idx)
	{
		mddolog("Route %s/%u goes over wrong interface %u instead of %u\n",
			dst, rtm->rtm_dst_len, idx, iface->kernel_ifindex);
		resync = true;
	}

	/* Which prefix is it? (local/remote/subnet) */
	if (memcmp(dest, &iface->ipv6_us, sizeof(iface->ipv6_us)) == 0)
	{
		if (!resync && !rem)
		{
			mddolog("Local Route is synced for %s\n", iface->name);
			iface->synced_local = true;
		}
	}
	else if (memcmp(dest, &iface->ipv6_them, sizeof(iface->ipv6_them)) == 0)
	{
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
			if (	subnet->is_tunnel ||
				memcmp(dest, &subnet->prefix, sizeof(subnet->prefix)) != 0)
			{
				continue;
			}

			/* It's one of ours, keep it */
			rem = false;

			/* Mark this one as synced */
			subnet->synced = true;

			/* Most interfaces only have one subnet thus just mark it up */
			iface->synced_subnet = true;

			mddolog("SUBNET %s/%u on %s\n", dst, rtm->rtm_dst_len, iface->name);
			break;
		}

		if (rem) mddolog("Removing %s/%u on %s\n", dst, rtm->rtm_dst_len, iface->name);
	}

	if ((rem || resync) && g_conf->do_sync)
	{
		/* Remove the prefix */
		/* XXX: Might need to specify the correct interface */
		mddolog("Removing %s/%u due to mismatch\n", dst, rtm->rtm_dst_len);
		os_exec("ip -6 ro del %s/%u", dst, rtm->rtm_dst_len);

		if (resync && iface->state == IFSTATE_UP)
		{
			/* Need to bring it up? (effectively reconfiguring it) */
			os_exec("ip -6 ro add %s/%u dev %s", dst, rtm->rtm_dst_len, iface->name);
		}
	}

	OS_Mutex_Release(&iface->mutex, "netlink_update_route");
	return;
}

/* Receive message from netlink interface and pass those information
   to the given function. */
int os_netlink_parse_info(struct nlsock *nl);
int os_netlink_parse_info(struct nlsock *nl)
{
	char			buf[8192];
	int			status;
	unsigned int		status2;
	int			ret = 0;
	bool			done = false;
	struct iovec		iov;
	struct sockaddr_nl	snl;
	struct msghdr		msg;
	struct nlmsghdr		*h;

	while (g_conf && g_conf->running && !done)
	{
		iov.iov_base		= buf;
		iov.iov_len		= sizeof(buf);
		memset(buf, 0, sizeof(buf));

		msg.msg_name		= &snl;
		msg.msg_namelen		= sizeof(snl);
		msg.msg_iov		= &iov;
		msg.msg_iovlen		= 1;
		msg.msg_control		= NULL;
		msg.msg_controllen	= 0;
		msg.msg_flags		= 0;

		status = recvmsg(nl->sock, &msg, 0);

		if (status < 0)
		{
			if (errno == EINTR) continue;
			if (errno == EWOULDBLOCK || errno == EAGAIN) break;
			mdolog(LOG_ERR, "%s recvmsg overrun\n", nl->name);
			continue;
		}

		if (status == 0)
		{
			mdolog(LOG_ERR, "%s EOF\n", nl->name);
			return -1;
		}

		if (msg.msg_namelen != sizeof(snl))
		{
			mdolog(LOG_ERR, "%s sender address length error: length %d\n", nl->name, msg.msg_namelen);
			return -1;
		}

		/* Ignore messages that aren't from the kernel */
		if (snl.nl_pid != 0)
		{
			mdolog(LOG_ERR, "Skipping message from pid %u, %u bytes\n", snl.nl_pid, status);
			continue;
		}

		status2 = status;

		for (h = (struct nlmsghdr *)buf; !done && NLMSG_OK(h, status2); h = NLMSG_NEXT(h, status2))
		{
			/* Finish of reading. */
			if (h->nlmsg_type == NLMSG_DONE)
			{
				done = true;
				continue;
			}

			/* Error handling. */
			if (h->nlmsg_type == NLMSG_ERROR)
			{
				struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);

				/* If the error field is zero, then this is an ACK */
				if (err->error == 0)
				{
					mddolog("%s: %s ACK: type=%s(%u), seq=%u, pid=%d\n",
						__FUNCTION__, nl->name,
						lookup(nlmsg_str, err->msg.nlmsg_type),
						err->msg.nlmsg_type, err->msg.nlmsg_seq,
						err->msg.nlmsg_pid);

					/* return if not a multipart message, otherwise continue */
					if (!(h->nlmsg_flags & NLM_F_MULTI))
					{
						return 0;
					}
					continue;
				}

				if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
				{
					mdolog(LOG_ERR, "%s error: message truncated\n", nl->name);
					return -1;
				}

				mdolog(	(nl == &os_netlink_cmd &&
					(err->error == -ENODEV || err->error == -ESRCH) &&
					(err->msg.nlmsg_type == RTM_NEWROUTE || err->msg.nlmsg_type == RTM_DELROUTE)) ?
					LOG_DEBUG : LOG_ERR,
					"%s error: %s, type=%s(%u), seq=%u, pid=%d\n",
					nl->name, strerror_r(-err->error, buf, sizeof(buf)),
					lookup(nlmsg_str, err->msg.nlmsg_type),
					err->msg.nlmsg_type,
					err->msg.nlmsg_seq,
					err->msg.nlmsg_pid);
				return -1;
			}

			/* OK we got netlink message. */
			/*
			mddolog("netlink_parse_info(%s) type %s(%u), seq=%u, pid=%d\n",
				nl->name,
				lookup(nlmsg_str, h->nlmsg_type), h->nlmsg_type,
				h->nlmsg_seq, h->nlmsg_pid);
			*/

			if (h->nlmsg_type == RTM_NEWLINK || h->nlmsg_type == RTM_DELLINK)
			{
				netlink_update_link(h);
			}
			else if (h->nlmsg_type == RTM_NEWADDR || h->nlmsg_type == RTM_DELADDR)
			{
				netlink_update_address(h);
			}
			else if (h->nlmsg_type == RTM_NEWROUTE || h->nlmsg_type == RTM_DELROUTE)
			{
				netlink_update_route(h);
			}

			/* skip unsolicited messages originating from command socket */
			if (nl != &os_netlink_cmd && h->nlmsg_pid == os_netlink_cmd.snl.nl_pid)
			{
				mddolog("netlink_parse_info: %s packet comes from %s\n",
					nl->name, os_netlink_cmd.name);
				continue;
			}
		}

		/* After error care. */
		if (msg.msg_flags & MSG_TRUNC)
		{
			mdolog(LOG_ERR, "%s error: message truncated\n", nl->name);
			continue;
		}
		if (status2)
		{
			mdolog(LOG_ERR, "%s error: data remnant size %d/%d\n", nl->name, status2, status);
			return -1;
		}
	}
	return ret;
}

int os_socket(struct nlsock *nl, unsigned long groups, const char *name);
int os_socket(struct nlsock *nl, unsigned long groups, const char *name)
{
	int			ret;
	struct sockaddr_nl	snl;
	int			sock;
	unsigned int		namelen;
	uint32_t		oldsize, oldlen, newsize = (2*1024*1024), newlen;

	memset(nl, 0, sizeof(*nl));
	nl->name = name;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0)
	{
		char buf[256];
		mdolog(LOG_ERR, "Can't open %s socket: %s (%d)\n", nl->name, strerror_r(errno, buf, sizeof(buf)), errno);
		return -1;
	}

	ret = fcntl(sock, F_SETFL, O_NONBLOCK);
	if (ret < 0)
	{
		char buf[256];
		mdolog(LOG_ERR, "Can't set %s socket flags: %s (%d)\n", nl->name, strerror_r(errno, buf, sizeof(buf)), errno);
		close(sock);
		return -1;
	}

	oldlen = sizeof(oldsize);
	newlen = sizeof(newsize);

	ret = getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &oldsize, &oldlen);
	if (ret < 0)
	{
		char buf[256];
		mdolog(LOG_ERR, "Can't get %s receive buffer size: %s (%d)\n", nl->name, strerror_r(errno, buf, sizeof(buf)), errno);
		close(sock);
		return -1;
	}

	if (oldsize < newsize)
	{
		ret = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &newsize, sizeof(newsize));
		if (ret < 0)
		{
			char buf[256];
			mdolog(LOG_ERR, "Can't get %s receive buffer size: %s (%d)\n", nl->name, strerror_r(errno, buf, sizeof(buf)), errno);
			close(sock);
			return -1;
		}
		mdolog(LOG_INFO, "Set netlink socket receive buffer size from %u to %u\n", oldsize, newsize);
	}
	else
	{
		mdolog(LOG_INFO, "Netlink socket receive buffer size was already %u while wanted %u\n", oldsize, newsize);
	}

	memset(&snl, 0, sizeof(snl));
	snl.nl_family = AF_NETLINK;
	snl.nl_groups = groups;

	/* Bind the socket to the netlink structure for anything. */
	ret = bind(sock, (struct sockaddr *)&snl, sizeof(snl));
	if (ret < 0)
	{
		char buf[256];
		mdolog(LOG_ERR, "Can't bind %s socket to group 0x%x: %s (%d)\n", nl->name, snl.nl_groups, strerror_r(errno, buf, sizeof(buf)), errno);
		close(sock);
		return -1;
	}

	/* multiple netlink sockets will have different nl_pid */
	namelen = sizeof(snl);
	ret = getsockname(sock, (struct sockaddr *)&snl, &namelen);
	if (ret < 0 || namelen != sizeof(snl))
	{
		char buf[256];
		mdolog(LOG_ERR, "Can't get %s socket name: %s (%d)\n", nl->name, strerror_r(errno, buf, sizeof(buf)), errno);
		close(sock);
		return -1;
	}

	nl->snl = snl;
	nl->sock = sock;

	socket_setblock(sock);

	return ret;
}

int os_netlink_request(int family, int type, struct nlsock *nl);
int os_netlink_request(int family, int type, struct nlsock *nl)
{
	struct sockaddr_nl	snl;

	struct
	{
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;

	/* Check netlink socket. */
	if (nl->sock < 0)
	{
		mdolog(LOG_ERR, "%s socket isn't active\n", nl->name);
		return -1;
	}

	memset(&snl, 0, sizeof(snl));
	snl.nl_family = AF_NETLINK;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = type;
	req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = ++nl->seq;
	req.g.rtgen_family = family;

	return sendto(nl->sock, (void *)&req, sizeof(req), 0, (struct sockaddr *)&snl, sizeof(snl));
}

/* Public functions */
bool os_sync_complete(void)
{
	char	buf[256];
	int	ret;

	if (!os_initialized)
	{
		mdolog(LOG_ERR, "os_sync_complete() - Not initialized yet!\n");
		return false;
	}

	/* Request table updates and see if everything is still correct */

	/* Check Links */
	ret = os_netlink_request(AF_PACKET, RTM_GETLINK, &os_netlink_cmd);
	if (ret < 0)
	{
		mdolog(LOG_ERR, "os_sync_complete(GETLINK): %s (%d)\n", strerror_r(errno, buf, sizeof(buf)), errno);
		return false;
	}
	ret = os_netlink_parse_info(&os_netlink_cmd);
	if (ret < 0)
	{
		mdolog(LOG_ERR, "os_sync_complete(GETLINK2): %s (%d)\n", strerror_r(errno, buf, sizeof(buf)), errno);
		return false;
	}

	/* Check IPv6 Addresses */
	ret = os_netlink_request(AF_INET6, RTM_GETADDR, &os_netlink_cmd);
	if (ret < 0)
	{
		mdolog(LOG_ERR, "os_sync_complete(GETADDR): %s (%d)\n", strerror_r(errno, buf, sizeof(buf)), errno);
		return false;
	}
	ret = os_netlink_parse_info(&os_netlink_cmd);
	if (ret < 0)
	{
		mdolog(LOG_ERR, "os_sync_complete(GETADDR2): %s (%d)\n", strerror_r(errno, buf, sizeof(buf)), errno);
		return false;
	}

	/* Check IPv6 Routes */
	ret = os_netlink_request(AF_INET6, RTM_GETROUTE, &os_netlink_cmd);
	if (ret < 0)
	{
		mdolog(LOG_ERR, "os_sync_complete(GETROUTE): %s (%d)\n", strerror_r(errno, buf, sizeof(buf)), errno);
		return false;
	}
	ret = os_netlink_parse_info(&os_netlink_cmd);
	if (ret < 0)
	{
		mdolog(LOG_ERR, "os_sync_complete(GETROUTE2): %s (%d)\n", strerror_r(errno, buf, sizeof(buf)), errno);
		return false;
	}

	return false;
}

void *os_dthread(void UNUSED *arg);
void *os_dthread(void UNUSED *arg)
{
	/* Show that we have started */
	mdolog(LOG_INFO, "OS Handler: Linux - started\n");

	/* Parse updates */
	os_netlink_parse_info(&os_netlink);

	mdolog(LOG_INFO, "OS Handler: Linux - exiting\n");

	return NULL;
}

/* Initialze OS Handler, might start a thread */
bool os_init()
{
	unsigned long groups;

	/* Don't init twice */
	if (os_initialized) return true;

	/* We are done */
	os_initialized = true;

	/* Set sysconf stuff making sure this is set ;) */
	os_exec("sysctl -q -w net.ipv6.conf.default.forwarding=1");
	os_exec("sysctl -q -w net.ipv6.conf.all.forwarding=1");

	/* XXX - Some PoPs might use RA to configure themselves :( */
	/*
	os_exec("sysctl -q -w net.ipv6.conf.default.accept_ra=0");
	os_exec("sysctl -q -w net.ipv6.conf.all.accept_ra=0");
	*/

	/* Buffersize adjustments */
	os_exec("sysctl -q -w net.core.rmem_default=65536");
	os_exec("sysctl -q -w net.core.wmem_default=65536");
	os_exec("sysctl -q -w net.core.rmem_max=8388608");
	os_exec("sysctl -q -w net.core.wmem_max=8388608");
	os_exec("sysctl -q -w net.ipv6.route.max_size=131072");

	/* Our interrests */
	groups = RTMGRP_LINK |
		RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_IFADDR |
		RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR;

	/* Build the sockets */
	os_socket(&os_netlink, groups, "in");
	os_socket(&os_netlink_cmd, 0, "cmd");

	/*
	 * Create a thread for handling updates from the OS
	 * Our own changes (using the cmd channel) will also be seen here)
	 */
	thread_add("OS", os_dthread, NULL, true);

	return true;
}

