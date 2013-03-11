/**********************************************************
 SixXSd - SixXS PoP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2013 All Rights Reserved
**********************************************************/

#ifndef PROTO41_H
#define PROTO41_H "Protocol 41"

#include "sixxsd.h"

VOID proto41_in(const IPADDRESS *src, uint8_t *packet, const uint32_t len);
VOID proto41_out(const uint16_t in_tid, const uint16_t out_tid, const uint8_t *packet, const uint16_t len, BOOL is_response);

#endif

