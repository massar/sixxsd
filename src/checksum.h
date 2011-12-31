/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2011 All Rights Reserved
***********************************************************/

#ifndef CHECKSUM_H
#define CHECKSUM_H "Checksum"

uint16_t in_checksum		(const unsigned char *data, uint16_t length);
uint16_t ipv6_checksum		(const struct ip6_hdr *ip6, const uint8_t protocol, const VOID *data, const uint16_t length);

#endif /* CHECKSUM_H */

