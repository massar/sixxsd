# sixxsd

"sixxsd" is the SixXS Daemon, it is the software that used to run on the [SixXS](https://www.sixxs.net/) PoPs 
and that handled the server-side of proto-41, heartbeat and AYIYA tunnels.

sixxsd was designed and implemented by [Jeroen Massar](https://jeroen.massar.ch).

[SixXS was sunset on 2017-06-06](https://www.sixxs.net/sunset/) after 17 years of operation as a free
[IPv6 Tunnel Broker](https://en.wikipedia.org/wiki/Tunnel_broker) service for users worldwide.

sixxsd ran on the PoPs from 2004 till 2017, serving an active daily 50.000 tunnels spread over 50 PoPs (with some PoPs being small <100 tunnels, others having >3000 tunnels per host).
Before sixxsd existed several bash scripts would reconfigure the kernel's gif interfaces.

## Important Historic Notice

*THIS CODE IS HISTORIC AND INTENDED FOR REFERENCE ONLY*

sixxsd is provided for HISTORIC purposes, to show an insight into
how SixXS handled provisioning massive amounts of tunnels on
many PoPs around the world.

SixXS shut down as IPv6 and deploying it is happening for 20+ years...
Thus, please, finally, get *native* IPv6!!!!!

If you need a tunneling solution fit for 2017 and beyond: use Wireguard!
Do not send plaintext traffic over the Internet as is the case with
proto-41, heartbeat and AYIYA tunnels.

Please also note that because of the cleartext various attacks are actually
possible that can affect operation of such tunnels. MD5 used by heartbeat
is easily fakeable, AYIYA uses good old SHA1 as a hash signature.

As such, we repeat again: sixxsd is intended for historic insight,
do not operate anymore on the public Internet.

## Operation

In effect sixxsd is SixXS's own routing platform as the complete process of en/decapsulation of tunneled
packets and passing it to the proper location is handled by it.

sixxsd also takes care of the latency tests and traffic statistic collection.
Various statistics can be seen, when logged in, in real-time from the user home under tunnel details,
e.g. the current location of an endpoint of a tunnel.

sixxsd exists as the Linux kernel has/was not been designed to handle thousands of network interfaces: every packet was walking over a linked list.
Adding/removing/reconfiguring interfaces was also prone to disconnects between what the system thought happened and what the actual configuration was.
Next to that a lot of tuning due to routing table size was needed and various other issues we ran into over time.

The model that sixxsd uses is that of a single tun/tap interface exposed by the kernel where one or more /40's are routed into.
This releases the kernel from any of the management of this address space and all the interfaces that are located there.
sixxsd effectively runs 'statically', nothing changes (no memory allocations etc) after it has been started.
Elements for configuration have all been pre-allocated, thus avoiding out of memory issues or memory fragmentation issues.
As we know the address-space layout, sixxsd is optimized for that, which avoids the need for table lookups or linked lists for routing packets.

This model also means that sixxsd sees all the packets and thus is able to provide accurate counters for performance monitoring.

## Features

A short summary of features of sixxsd:

 - Handles the full IPv6 Routing process
 - En/Decapsulation of protocol-41 (6in4/[RFC3056](https://tools.ietf.org/html/rfc3056)) and AYIYA (IPv4 in IPv6-UDP and IPv6 in IPv4-UDP)
 - Very high performance (during tests easily forwarded 4 Gbit/s of mixed AYIYA/proto-41 traffic)
 - IPv6 Tunnel Heartbeat support
 - Latency testing of active endpoints
 - Per-tunnel remote debugging option showing per-packet decisions being made
 - Per-tunnel statistics and error information
 - Per-tunnel default routed /64 towards tunnel endpoint

## Configuration

The sixxsd binary starts by reading a [sixxsd.conf](misc/sixxsd.conf) this instructs it which prefixes it handles and which it routes to the tunnel device.
It uses a standard tun/tap device as provided by most Unix-alike kernels. 

The SixXS backend, which can get updated by users using the webinterface, re-pushes the full configuration to the PoP.
This directly updates the state for all the interfaces and routes.

The ```pop saveconfig``` command atomically saves the sixxsd.conf running configuration to disk.
Thus allowing a restart of the PoP to resume with that state of configuration till a configuration push updates the configuration again.

## Stability

As SixXS only deployed minimal kernels the PoPs where sixxsd ran where extremely stable and ran for multiple years at a time.

Some details from when we shutdown all the PoPs:
```
Daemon uptime:
nlams05.sixxs.net: 901 days 01:41:44
usanc01.sixxs.net: 826 days 00:32:10
nlede01.sixxs.net: 826 days 01:02:11
fihel01.sixxs.net: 826 days 00:27:25
usbos01.sixxs.net: 821 days 18:36:37
deham02.sixxs.net: 821 days 18:39:21
deham01.sixxs.net: 821 days 18:39:25
ausyd01.sixxs.net: 821 days 18:40:08
aubne01.sixxs.net: 821 days 18:45:04
deleo01.sixxs.net: 802 days 23:07:44

Server uptime:
deham02.sixxs.net: 1893 days 00:05:17
usbos01.sixxs.net: 1876 days 06:59:03
deham01.sixxs.net: 1610 days 17:44:19
fihel01.sixxs.net: 1581 days 15:17:46
nlede01.sixxs.net: 1260 days 01:49:58
ausyd01.sixxs.net: 1082 days 06:05:18
aubne01.sixxs.net: 1082 days 06:00:58
nlams05.sixxs.net: 1064 days 10:04:58
usanc01.sixxs.net: 879 days 23:33:28
deleo01.sixxs.net: 802 days 23:09:10
```

That demonstrates an uptime of about 2,5 years of active running indicating how stable it ran.
Especially considering when one realises how many packets these daemons where forwarding, while
being reconfigured every 10 minutes from the central server and also by heartbeat and AYIYA clients.

## Platforms

sixxsd was primarily run on minimal Debian GNU/Linux systems, but also ran on FreeBSD and OpenBSD based PoPs.
In addition, for development, MacOS also functions, but primarily for development, not for actual operation.

## Support / Status

The code is provided as-as, primarily for historical purposes as various people have requested insight into what actually drove the SixXS PoPs.

Due to the state of IPv6 deployment, we hope that this code is not needed anymore anywhere: please finally get native IPv6, it has been more than 20 years...

If one wants to create a VPN-alike service, we heavily suggest looking at [Wireguard](https://www.wireguard.com/) and/or OpenVPN instead as these
provide secure (read: cryptography involved) tunnels which disallow snooping along. All protocols implemented by sixxsd are insecure: no cryptography involved.

See also above the historic notice.

## Security

As one will notice, no TLS or even SSL is included in this code, the SixXS PoPs where reconfigured over SSH tunneled TCP connections.

Any current modern tunneling solution will use proper cryptography, hence, please look at Wireguard.

* proto-41, heartbeat and AYIYA are all cleartext
* The heartbeat protocol uses good old MD5
* The AYIYA protocol uses good old SHA-1

All of these do not make a secure system.

## Monitoring

The [check_sixxsd.py](misc/check_sixxsd.py) script was used for monitoring sixxsd instances.

This was quite useful, as we monitored active tunnels, if they dropped below a certain level we would know that something was wrong on our side.
Figuring out then what, was the fun exercise.

## License

The license for sixxsd is the BSD 3-clause license.

In case one uses/references this, don't hesitate to give a shout out to the author, it is much appreciated.

## Author

The designer and implementor of sixxsd is [Jeroen Massar](https://jeroen.massar.ch).

## Contact

Jeroen can be reached by email: [jeroen@massar.ch](mailto:jeroen@massar.ch).

The previous email SixXS addresses. (jeroen@sixxs.net and info@sixxs.net) have been deactived when the project sunset.
