/**************************************
 SixXSd - SixXS POP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
***************************************
 $Author: jeroen $
 $Id: os_linux.c,v 1.4 2005-04-05 17:38:30 jeroen Exp $
 $Date: 2005-04-05 17:38:30 $

 SixXSd - Linux specific code
**************************************/

#include "sixxsd.h"

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/* Socket interface to kernel */
struct nlsock
{
  int sock;
  int seq;
  struct sockaddr_nl snl;
  char *name;
};

/* netlink      = { -1, 0, {0}, "netlink-listen"},	// kernel messages
  netlink_cmd  = { -1, 0, {0}, "netlink-cmd"},		// command channel
  netlink_addr = { -1, 0, {0}, "netlink-addr"};		// address channel
*/

struct nlsock os_netlink, os_netlink_cmd;

/* OS Helper functions */

void os_log(int level, char *fmt, ...)
{
	char buf[1024];
	
	// Print the host+port this is coming from
	snprintf(buf, sizeof(buf), "[OS:0x%x] : ", (unsigned int)pthread_self());

	// Print the log message behind it
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf+strlen(buf), sizeof(buf)-strlen(buf), fmt, ap);
	va_end(ap);
	
	// Actually Log it
	dolog(level, buf);
}

void os_exec(char *fmt, ...)
{
	char buf[1024];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf,sizeof(buf),fmt,ap);
	D(dolog(LOG_DEBUG, "os_exec(\"%s\")\n", buf));
	system(buf);
	va_end(ap);
}


/* Message structure. */
struct message
{
	int key;
	char *str;
};

struct message nlmsg_str[] = {
  {RTM_NEWROUTE, "RTM_NEWROUTE"},
  {RTM_DELROUTE, "RTM_DELROUTE"},
  {RTM_GETROUTE, "RTM_GETROUTE"},
  {RTM_NEWLINK,  "RTM_NEWLINK"},
  {RTM_DELLINK,  "RTM_DELLINK"},
  {RTM_GETLINK,  "RTM_GETLINK"},
  {RTM_NEWADDR,  "RTM_NEWADDR"},
  {RTM_DELADDR,  "RTM_DELADDR"},
  {RTM_GETADDR,  "RTM_GETADDR"},
  {0, NULL}
};

/* Message lookup function. */
char *lookup(struct message *mes, int key)
{
	struct message *pnt;
	
	for (pnt = mes; pnt->key != 0; pnt++)
	if (pnt->key == key) return pnt->str;
	
	return "";
}

/* Receive message from netlink interface and pass those information
   to the given function. */
int os_netlink_parse_info(int (*filter)(struct sockaddr_nl *, struct nlmsghdr *), struct nlsock *nl)
{
	int status;
	unsigned int status2;
	int ret = 0;
	int error;

	while (1)
	{
		char buf[4096];
		struct iovec iov = { buf, sizeof buf };
		struct sockaddr_nl snl;
		struct msghdr msg = { (void *) &snl, sizeof snl, &iov, 1, NULL, 0, 0 };
		struct nlmsghdr *h;

		status = recvmsg (nl->sock, &msg, 0);

		if (status < 0)
		{
			if (errno == EINTR) continue;
			if (errno == EWOULDBLOCK || errno == EAGAIN) break;
			os_log(LOG_ERR, "%s recvmsg overrun", nl->name);
			continue;
		}

		if (status == 0)
		{
			os_log(LOG_ERR, "%s EOF", nl->name);
			return -1;
		}

		if (msg.msg_namelen != sizeof snl)
		{
			os_log(LOG_ERR, "%s sender address length error: length %d",
 nl->name, msg.msg_namelen);
			return -1;
		}

		/* Ignore messages that aren't from the kernel */
		if ( snl.nl_pid != 0 )
		{
			os_log(LOG_ERR, "Ignoring message from pid %u", snl.nl_pid );
			continue;
		}

		status2 = status;

		for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, status2); h = NLMSG_NEXT(h, status2))
		{
			/* Finish of reading. */
			if (h->nlmsg_type == NLMSG_DONE) return ret;

			/* Error handling. */
			if (h->nlmsg_type == NLMSG_ERROR)
			{
				struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA (h);

				/* If the error field is zero, then this is an ACK */
				if (err->error == 0)
				{
					D(os_log(LOG_DEBUG,
						"%s: %s ACK: type=%s(%u), seq=%u, pid=%d",
						__FUNCTION__, nl->name,
						lookup(nlmsg_str, err->msg.nlmsg_type),
						err->msg.nlmsg_type, err->msg.nlmsg_seq,
						err->msg.nlmsg_pid);)

					/* return if not a multipart message, otherwise continue */
					if (!(h->nlmsg_flags & NLM_F_MULTI))
					{
						return 0;
					}
					continue;
				}

				if (h->nlmsg_len < NLMSG_LENGTH (sizeof (struct nlmsgerr)))
				{
					os_log(LOG_ERR, "%s error: message truncated", nl->name);
					return -1;
				}

				os_log(	(nl == &os_netlink_cmd
					&& (err->error == -ENODEV || err->error == -ESRCH)
					&& (err->msg.nlmsg_type == RTM_NEWROUTE || err->msg.nlmsg_type == RTM_DELROUTE)) ?
					LOG_DEBUG : LOG_ERR,
					"%s error: %s, type=%s(%u), "
					"seq=%u, pid=%d",
					nl->name, strerror(-(err->error)),
					lookup(nlmsg_str, err->msg.nlmsg_type),
					err->msg.nlmsg_type,
					err->msg.nlmsg_seq,
					err->msg.nlmsg_pid);
				/*
				ret = -1;
				continue;
				*/
				return -1;
			}

			/* OK we got netlink message. */
			D(os_log(LOG_DEBUG,
				"netlink_parse_info: %s type %s(%u), seq=%u, pid=%d",
				nl->name,
				lookup (nlmsg_str, h->nlmsg_type), h->nlmsg_type,
				h->nlmsg_seq, h->nlmsg_pid);)

			/* skip unsolicited messages originating from command socket */
			if (nl != &os_netlink_cmd && h->nlmsg_pid == os_netlink_cmd.snl.nl_pid)
			{
				D(os_log(LOG_DEBUG,
					"netlink_parse_info: %s packet comes from %s",
					nl->name, os_netlink_cmd.name);)
				continue;
			}

			error = (*filter) (&snl, h);
			if (error < 0)
			{
				os_log(LOG_ERR, "%s filter function error", nl->name);
				ret = error;
			}
		}

		/* After error care. */
		if (msg.msg_flags & MSG_TRUNC)
		{
			os_log(LOG_ERR, "%s error: message truncated", nl->name);
			continue;
		}
		if (status)
		{
			os_log(LOG_ERR, "%s error: data remnant size %d", nl->name,
			status);
			return -1;
		}
	}
	return ret;
}

int os_socket(struct nlsock *nl, unsigned long groups)
{
	int ret;
	struct sockaddr_nl snl;
	int sock;
	int namelen;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0)
	{
		os_log(LOG_ERR, "Can't open %s socket: %s", nl->name, strerror (errno));
		return -1;
	}

	ret = fcntl (sock, F_SETFL, O_NONBLOCK);
	if (ret < 0)
	{
		os_log(LOG_ERR, "Can't set %s socket flags: %s", nl->name, strerror (errno));
		close(sock);
		return -1;
	}

	memset(&snl, 0, sizeof snl);
	snl.nl_family = AF_NETLINK;
	snl.nl_groups = groups;

	/* Bind the socket to the netlink structure for anything. */
	ret = bind (sock, (struct sockaddr *) &snl, sizeof snl);
	if (ret < 0)
	{
		os_log(LOG_ERR, "Can't bind %s socket to group 0x%x: %s", nl->name, snl.nl_groups, strerror (errno));
		close(sock);
		return -1;
	}

	/* multiple netlink sockets will have different nl_pid */
	namelen = sizeof snl;
	ret = getsockname(sock, (struct sockaddr *)&snl, &namelen);
	if (ret < 0 || namelen != sizeof snl)
	{
		os_log(LOG_ERR, "Can't get %s socket name: %s", nl->name, strerror (errno));
		close(sock);
		return -1;
	}

	nl->snl = snl;
	nl->sock = sock;
	return ret;
}

/* Public functions */
bool os_sync_complete()
{
	D(dolog(LOG_DEBUG, "linux::os_sync_complete();\n");)
	return false;
}

bool os_sync_interface_up(struct sixxs_interface *iface)
{
	char ipv6_us[100], ipv6_them[100];

	inet_ntop(AF_INET6, &iface->ipv6_us, ipv6_us, sizeof(ipv6_us));
	inet_ntop(AF_INET6, &iface->ipv6_them, ipv6_them, sizeof(ipv6_them));

	if (	iface->type == IFACE_PROTO41 ||
		iface->type == IFACE_PROTO41_HB)
	{
		char ipv4_us[100], ipv4_them[100];

		inet_ntop(AF_INET, &iface->ipv4_us, ipv4_us, sizeof(ipv4_us));
		inet_ntop(AF_INET, &iface->ipv4_them, ipv4_them, sizeof(ipv4_them));

		os_exec(
			"ip tunnel add %s mode sit local %s remote %s",
			iface->name,
			ipv4_us,
			ipv4_them);
	}

	os_exec(
		"ip link set %s up",
		iface->name);

	os_exec(
		"ip link set mtu %u dev %s",
		iface->mtu, iface->name);

	if (	iface->type == IFACE_PROTO41 ||
		iface->type == IFACE_PROTO41_HB)
	{
		os_exec(
			"ip tunnel change %s ttl 64",
			iface->name);
	}

	if (	iface->type == IFACE_AYIYA)
	{
		/* Set the link local address */
		char ipv6_ll[100];
		inet_ntop(AF_INET6, &iface->ipv6_ll, ipv6_ll, sizeof(ipv6_ll));
		os_exec(
			"ip -6 addr add %s/%u dev %s",
			ipv6_ll,
			64,
			iface->name);
	}

	os_exec(
		"ip -6 addr add %s/%u dev %s",
		ipv6_us,
		// we only route /128 tunnels
		128,
		iface->name);

	os_exec(
		"ip -6 ro add %s/%u dev %s",
		ipv6_them,
		// we only route /128 tunnels
		128,
		iface->name);

	return true;
}

bool os_sync_interface_down(struct sixxs_interface *iface)
{
	char ipv6_us[100], ipv6_them[100];

	inet_ntop(AF_INET6, &iface->ipv6_us, ipv6_us, sizeof(ipv6_us));
	inet_ntop(AF_INET6, &iface->ipv6_them, ipv6_them, sizeof(ipv6_them));

	os_exec(
		"ip -6 ro del %s/%u dev %s",
		ipv6_them,
		128,
		iface->name);

	os_exec(
		"ip -6 addr del %s/%u dev %s",
		ipv6_us,
		// we only route /128 tunnels
		128,
		iface->name);

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

	return true;
}

bool os_sync_interface(struct sixxs_interface *iface)
{
	D(dolog(LOG_DEBUG, "linux::os_sync_interface(%s, %s);\n", iface->name, iface->state == IFSTATE_UP ? "up" : "down/disabled");)

	if (iface->state == IFSTATE_UP) return os_sync_interface_up(iface);

	return os_sync_interface_down(iface);
}

void *os_thread(void *arg)
{
	unsigned long groups;
	int ret;

	// Show that we have started
	os_log(LOG_INFO, "OS Handler: Linux\n");

	// Our interrests
	groups = RTMGRP_LINK |
		RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_IFADDR |
		RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR;

	// Build the sockets
	os_socket(&os_netlink, groups);
	os_socket(&os_netlink_cmd, 0);
	
	ret = os_netlink_parse_info(NULL, &os_netlink);
	
	return NULL;
}

// Initialze OS Handler, might start a thread
bool os_init()
{
	// Create a thread for the OS
//DIS	thread_add("OS", os_thread, NULL);
	return true;
}
