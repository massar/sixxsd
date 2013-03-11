/**********************************************************
 SixXSd - SixXS PoP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2013 All Rights Reserved
**********************************************************/

#ifndef ICMPV4_H
#define ICMPV4_H "ICMPv4"

#include "sixxsd.h"

VOID icmpv4_in(const IPADDRESS *org, uint8_t *packet, const uint32_t len);

#endif

