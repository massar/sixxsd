/**********************************************************
 SixXSd - SixXS PoP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2013 All Rights Reserved
**********************************************************/

#ifndef HB_H
#define HB_H "Heartbeat"

#include "sixxsd.h"

#define HEARTBEAT_PORT 3740

VOID hb_in(const IPADDRESS *src, const uint8_t *packet, uint32_t len);

#endif

