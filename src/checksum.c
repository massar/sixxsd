/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2013 All Rights Reserved
***********************************************************/

#include "sixxsd.h"

const char module_checksum[] = "checksum";
#define module module_checksum

uint16_t ipv4_checksum(const unsigned char *buf, uint16_t len)
{
	int		odd, count;
	unsigned long	result = 0;

	if (len <= 0) return ~0;

	odd = 1 & (addressnum_t)buf;
	if (odd)
	{
#if BYTE_ORDER == LITTLE_ENDIAN
		result = *buf;
#else
		result += (*buf << 8);
#endif
		len--;
		buf++;
	}

	/* nr of 16-bit words.. */
	count = len >> 1;
	if (count)
	{
		if (2 & (addressnum_t)buf)
		{
			result += *(uint16_t *)buf;
			count--;
			len -= 2;
			buf += 2;
		}

		/* nr of 32-bit words.. */
		count >>= 1;

		if (count)
		{
			uint64_t carry = 0;

			do
			{
				uint64_t w = (*(uint16_t *)buf << 16) + (*(uint16_t *)&buf[2]);

				count--;
				buf += 4;
				result += carry;
				result += w;
				carry = (w > result);
			}
			while (count);

			result += carry;
			result = (result & UINT16_MAX) + (result >> 16);
		}

		if (len & 2)
		{
			result += *(uint16_t *)buf;
			buf += 2;
		}
	}

	if (len & 1)
	{
#if BYTE_ORDER == LITTLE_ENDIAN
		result += *buf;
#else
		result += (*buf << 8);
#endif
	}

	/* add up 16-bit and 16-bit for 16+c bit */
	result = (result & UINT16_MAX) + (result >> 16);

	/* add up carry.. */
	result = (result & UINT16_MAX) + (result >> 16);

	if (odd) result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);

	return result;
}

static uint64_t ipv6_checksumA(const uint8_t *a, unsigned int len);
static uint64_t ipv6_checksumA(const uint8_t *a, unsigned int len)
{
	uint64_t	chksum = 0;
	unsigned int	i = 0;

	while (i < len)
	{
		if (i++ % 2 == 0)	chksum += *a++;
		else			chksum += *a++ << 8;
	}

	return chksum;
}

uint16_t ipv6_checksum(const struct ip6_hdr *ip6, const uint8_t protocol, const VOID *data, const uint16_t length)
{
	struct
	{
		uint16_t	length;
		uint16_t	zero1;
		uint8_t		zero2;
		uint8_t		next;
	} pseudo;
	uint64_t chksum = 0;

	pseudo.length   = htons(length);
	pseudo.zero1    = 0;
	pseudo.zero2    = 0;
	pseudo.next     = protocol;

	chksum += ipv6_checksumA((uint8_t *)&ip6->ip6_src,	sizeof(ip6->ip6_src) * 2);
	chksum += ipv6_checksumA((uint8_t *)&pseudo,		sizeof(pseudo));
	chksum += ipv6_checksumA(data,				length);

	/* Wrap in the carries to reduce chksum to 16 bits. */
	chksum = (chksum & UINT16_MAX) + (chksum >> 16);

	/* Ones complement */
	chksum = ~chksum;

	return chksum;
}

