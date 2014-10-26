/**********************************************************
 SixXSd - SixXS PoP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2013 All Rights Reserved
**********************************************************/

#ifndef PROTO4_H
#define PROTO4_H "Protocol 4"

#include "sixxsd.h"

VOID proto4_in(const IPADDRESS *src, uint8_t *packet, const uint16_t len);
VOID proto4_out(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, BOOL is_response);

#endif

