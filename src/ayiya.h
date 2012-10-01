/**********************************************************
 SixXSd - SixXS PoP Daemon
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2012 All Rights Reserved
**********************************************************/

#ifndef AYIYA_H
#define AYIYA_H "5UU5N1K1"

#include "sixxsd.h"

/*
 * Anything In Anything - AYIYA
 */
#define AYIYA_PORT	5072

/*
 * AYIYA version (which document this should conform to)
 * Per draft-massar-v6ops-ayiya-02 (July 2004)
 */
#define AYIYA_VERSION	"draft-02"

enum ayiya_identities
{
	ayiya_id_none			= 0x0,	/* None */
	ayiya_id_integer		= 0x1,	/* Integer */
	ayiya_id_string			= 0x2	/* ASCII String */
};

enum ayiya_hash
{
	ayiya_hash_none			= 0x0,	/* No hash */
	ayiya_hash_md5			= 0x1,	/* MD5 Signature */
	ayiya_hash_sha1			= 0x2	/* SHA1 Signature */
};

enum ayiya_auth
{
	ayiya_auth_none			= 0x0,	/* No authentication */
	ayiya_auth_sharedsecret		= 0x1,	/* Shared Secret */
	ayiya_auth_pgp			= 0x2	/* Public/Private Key */
};

enum ayiya_opcode
{
	ayiya_op_noop			= 0x0,	/* No Operation */
	ayiya_op_forward		= 0x1,	/* Forward */
	ayiya_op_echo_request		= 0x2,	/* Echo Request */
	ayiya_op_echo_request_forward	= 0x3,	/* Echo Request and Forward */
	ayiya_op_echo_response		= 0x4,	/* Echo Response */
	ayiya_op_motd			= 0x5,	/* MOTD */
	ayiya_op_query_request		= 0x6,	/* Query Request */
	ayiya_op_query_response		= 0x7	/* Query Response */
};

struct ayiyahdr
{
#if BYTE_ORDER == BIG_ENDIAN
	u_int32_t	ayh_idlen:4;		/* Identity Length */
	u_int32_t	ayh_idtype:4;		/* Identity Type */
	u_int32_t	ayh_siglen:4;		/* Signature Length */
	u_int32_t	ayh_hshmeth:4;		/* Hashing Method */
	u_int32_t	ayh_autmeth:4;		/* Authentication Method */
	u_int32_t	ayh_opcode:4;		/* Operation Code */
	u_int32_t	ayh_nextheader:8;	/* Next Header (PROTO_*) */
#elif BYTE_ORDER == LITTLE_ENDIAN
	u_int32_t	ayh_idtype:4;		/* Identity Type */
	u_int32_t	ayh_idlen:4;		/* Identity Length */
	u_int32_t	ayh_hshmeth:4;		/* Hashing Method */
	u_int32_t	ayh_siglen:4;		/* Signature Length */
	u_int32_t	ayh_opcode:4;		/* Operation Code */
	u_int32_t	ayh_autmeth:4;		/* Authentication Method */
	u_int32_t	ayh_nextheader:8;	/* Next Header (PROTO_*) */
#else
#error unsupported endianness!
#endif
	u_int32_t	ayh_epochtime;		/* Time in seconds since "00:00:00 1970-01-01 UTC" */
};

VOID ayiya_in(const IPADDRESS *src, const uint8_t af, const uint8_t socktype, const uint8_t protocol, const uint16_t sport, const uint16_t dport, const uint8_t *packet, const uint32_t len);
VOID ayiya_out(const uint16_t in_tid, const uint16_t out_tid, const uint8_t protocol, const uint8_t *packet, const uint16_t len, BOOL is_response);
const char *ayiya_hash_name(enum ayiya_hash type);

#endif

