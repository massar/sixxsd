/**********************************************************
 AYIYA - Anything In Anything (with Authentication)
 by Jeroen Massar <jeroen@sixxs.net> / <jeroen@unfix.org>
**********************************************************/

#ifndef AYIYA_H
#define AYIYA_H "5UU5N1K1"

// Anything In Anything - AYIYA (uses UDP in our case)
// The port number spells BETA as there is no IANA assigned port.
#define AYIYA_PORT	"8374"

// AYIYA version (which document this should conform to)
// Per draft-massar-v6ops-ayiya-02 (July 2004)
#define AYIYA_VERSION	"draft-02"

enum ayiya_identities
{
	ayiya_id_none			= 0x0,	// None
	ayiya_id_integer		= 0x1,	// Integer
	ayiya_id_string			= 0x2,	// ASCII String
};

enum ayiya_hash
{
	ayiya_hash_none			= 0x0,	// No hash
	ayiya_hash_md5			= 0x1,	// MD5 Signature
	ayiya_hash_sha1			= 0x2,	// SHA1 Signature
};

enum ayiya_auth
{
	ayiya_auth_none			= 0x0,	// No authentication
	ayiya_auth_sharedsecret		= 0x1,	// Shared Secret
	ayiya_auth_pgp			= 0x2,	// Public/Private Key
};

enum ayiya_opcode
{
	ayiya_op_noop			= 0x0,	// No Operation
	ayiya_op_forward		= 0x1,	// Forward
	ayiya_op_echo_request		= 0x2,	// Echo Request
	ayiya_op_echo_request_forward	= 0x3,	// Echo Request and Forward
	ayiya_op_echo_response		= 0x4,	// Echo Response
	ayiya_op_motd			= 0x5,	// MOTD
	ayiya_op_query_request		= 0x6,	// Query Request
	ayiya_op_query_response		= 0x6,	// Query Response
};

struct ayiyahdr
{
#if __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t	ayh_idlen:4;		// Identity Length
	u_int8_t	ayh_idtype:4;		// Identity Type
	u_int8_t	ayh_siglen:4;		// Signature Length
	u_int8_t	ayh_hshmeth:4;		// Hashing Method
	u_int8_t	ayh_autmeth:4;		// Authentication Method
	u_int8_t	ayh_opcode:4;		// Operation Code
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t	ayh_idtype:4;		// Identity Type
	u_int8_t	ayh_idlen:4;		// Identity Length
	u_int8_t	ayh_hshmeth:4;		// Hashing Method
	u_int8_t	ayh_siglen:4;		// Signature Length
	u_int8_t	ayh_opcode:4;		// Operation Code
	u_int8_t	ayh_autmeth:4;		// Authentication Method
#else
#error unsupported endianness!
#endif
	u_int8_t	ayh_nextheader;		// Next Header (PROTO_*)
	u_int32_t	ayh_epochtime;		// Time in seconds since "00:00:00 1970-01-01 UTC"
};

#endif

