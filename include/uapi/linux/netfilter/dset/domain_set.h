/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _UAPI_DOMAIN_SET_H
#define _UAPI_DOMAIN_SET_H

#include <linux/types.h>

/* The protocol versions */
#define DSET_PROTOCOL 9
#define DSET_PROTOCOL_MIN 8

/* The max length of strings including NUL: set and type identifiers */
#define DSET_MAXNAMELEN 32

/* The maximum permissible comment length we will accept over netlink */
#define DSET_MAX_COMMENT_SIZE 255

/* The max length of domain */
#define DSET_MAX_DOMAIN_LEN 256

/* Message types and commands */
enum dset_cmd
{
	DSET_CMD_NONE,
	DSET_CMD_PROTOCOL,	/* 1: Return protocol version */
	DSET_CMD_CREATE,	  /* 2: Create a new (empty) set */
	DSET_CMD_DESTROY,	 /* 3: Destroy a (empty) set */
	DSET_CMD_FLUSH,		  /* 4: Remove all elements from a set */
	DSET_CMD_RENAME,	  /* 5: Rename a set */
	DSET_CMD_SWAP,		  /* 6: Swap two sets */
	DSET_CMD_LIST,		  /* 7: List sets */
	DSET_CMD_SAVE,		  /* 8: Save sets */
	DSET_CMD_ADD,		  /* 9: Add an element to a set */
	DSET_CMD_DEL,		  /* 10: Delete an element from a set */
	DSET_CMD_TEST,		  /* 11: Test an element in a set */
	DSET_CMD_HEADER,	  /* 12: Get set header data only */
	DSET_CMD_TYPE,		  /* 13: Get set type */
	DSET_CMD_GET_BYNAME,  /* 14: Get set index by name */
	DSET_CMD_GET_BYINDEX, /* 15: Get set name by index */
	DSET_MSG_MAX,		  /* Netlink message commands */

	/* Commands in userspace: */
	DSET_CMD_RESTORE = DSET_MSG_MAX, /* 16: Enter restore mode */
	DSET_CMD_HELP,					 /* 17: Get help */
	DSET_CMD_VERSION,				 /* 18: Get program version */
	DSET_CMD_QUIT,					 /* 19: Quit from interactive mode */

	DSET_CMD_MAX,

	DSET_CMD_COMMIT = DSET_CMD_MAX, /* 20: Commit buffered commands */
};

/* Attributes at command level */
enum
{
	DSET_ATTR_UNSPEC,
	DSET_ATTR_PROTOCOL,								 /* 1: Protocol version */
	DSET_ATTR_SETNAME,								 /* 2: Name of the set */
	DSET_ATTR_TYPENAME,								 /* 3: Typename */
	DSET_ATTR_SETNAME2 = DSET_ATTR_TYPENAME,		 /* Setname at rename/swap */
	DSET_ATTR_REVISION,								 /* 4: Settype revision */
	DSET_ATTR_FAMILY,								 /* 5: Settype family */
	DSET_ATTR_FLAGS,								 /* 6: Flags at command level */
	DSET_ATTR_DATA,									 /* 7: Nested attributes */
	DSET_ATTR_ADT,									 /* 8: Multiple data containers */
	DSET_ATTR_LINENO,								 /* 9: Restore lineno */
	DSET_ATTR_PROTOCOL_MIN,							 /* 10: Minimal supported version number */
	DSET_ATTR_REVISION_MIN = DSET_ATTR_PROTOCOL_MIN, /* type rev min */
	DSET_ATTR_INDEX,								 /* 11: Kernel index of set */
	__DSET_ATTR_CMD_MAX,
};
#define DSET_ATTR_CMD_MAX (__DSET_ATTR_CMD_MAX - 1)

/* CADT specific attributes */
enum
{
	DSET_ATTR_DOMAIN = DSET_ATTR_UNSPEC + 1,
	DSET_ATTR_TIMEOUT,						  /* 2 */
	DSET_ATTR_CADT_FLAGS,					  /* 3 */
	DSET_ATTR_CADT_LINENO = DSET_ATTR_LINENO, /* 9 */
	DSET_ATTR_CADT_MAX = 16,
	/* Create-only specific attributes */
	DSET_ATTR_GC,
	DSET_ATTR_HASHSIZE,
	DSET_ATTR_MAXELEM,
	// DSET_ATTR_NETMASK,
	DSET_ATTR_PROBES,
	DSET_ATTR_RESIZE,
	DSET_ATTR_SIZE,
	/* Kernel-only */
	DSET_ATTR_ELEMENTS,
	DSET_ATTR_REFERENCES,
	DSET_ATTR_MEMSIZE,

	__DSET_ATTR_CREATE_MAX,
};
#define DSET_ATTR_CREATE_MAX (__DSET_ATTR_CREATE_MAX - 1)

/* ADT specific attributes */
enum
{
	DSET_ATTR_NAME = DSET_ATTR_CADT_MAX + 1,
	DSET_ATTR_NAMEREF,
	DSET_ATTR_BYTES,
	DSET_ATTR_PACKETS,
	DSET_ATTR_COMMENT,
	DSET_ATTR_SKBMARK,
	DSET_ATTR_SKBPRIO,
	DSET_ATTR_SKBQUEUE,
	DSET_ATTR_PAD,
	__DSET_ATTR_ADT_MAX,
};
#define DSET_ATTR_ADT_MAX (__DSET_ATTR_ADT_MAX - 1)

/* IP specific attributes */
enum
{
	DSET_ATTR_IPADDR_IPV4 = DSET_ATTR_UNSPEC + 1,
	DSET_ATTR_IPADDR_IPV6,
	__DSET_ATTR_IPADDR_MAX,
};
#define DSET_ATTR_IPADDR_MAX (__DSET_ATTR_IPADDR_MAX - 1)

/* Error codes */
enum dset_errno
{
	DSET_ERR_PRIVATE = 4096,
	DSET_ERR_PROTOCOL,
	DSET_ERR_FIND_TYPE,
	DSET_ERR_MAX_SETS,
	DSET_ERR_BUSY,
	DSET_ERR_EXIST_SETNAME2,
	DSET_ERR_TYPE_MISMATCH,
	DSET_ERR_EXIST,
	DSET_ERR_INVALID_FAMILY,
	DSET_ERR_TIMEOUT,
	DSET_ERR_REFERENCED,
	DSET_ERR_COUNTER,
	DSET_ERR_COMMENT,
	DSET_ERR_SKBINFO,

	/* Type specific error codes */
	DSET_ERR_TYPE_SPECIFIC = 4352,
};

/* Flags at command level or match/target flags, lower half of cmdattrs*/
enum dset_cmd_flags
{
	DSET_FLAG_BIT_EXIST = 0,
	DSET_FLAG_EXIST = (1 << DSET_FLAG_BIT_EXIST),
	DSET_FLAG_BIT_LIST_SETNAME = 1,
	DSET_FLAG_LIST_SETNAME = (1 << DSET_FLAG_BIT_LIST_SETNAME),
	DSET_FLAG_BIT_LIST_HEADER = 2,
	DSET_FLAG_LIST_HEADER = (1 << DSET_FLAG_BIT_LIST_HEADER),
	DSET_FLAG_BIT_SKIP_COUNTER_UPDATE = 3,
	DSET_FLAG_SKIP_COUNTER_UPDATE =
		(1 << DSET_FLAG_BIT_SKIP_COUNTER_UPDATE),
	DSET_FLAG_BIT_SKIP_SUBCOUNTER_UPDATE = 4,
	DSET_FLAG_SKIP_SUBCOUNTER_UPDATE =
		(1 << DSET_FLAG_BIT_SKIP_SUBCOUNTER_UPDATE),
	DSET_FLAG_BIT_MATCH_COUNTERS = 5,
	DSET_FLAG_MATCH_COUNTERS = (1 << DSET_FLAG_BIT_MATCH_COUNTERS),
	DSET_FLAG_BIT_RETURN_NOMATCH = 7,
	DSET_FLAG_RETURN_NOMATCH = (1 << DSET_FLAG_BIT_RETURN_NOMATCH),
	DSET_FLAG_BIT_MAP_SKBMARK = 8,
	DSET_FLAG_MAP_SKBMARK = (1 << DSET_FLAG_BIT_MAP_SKBMARK),
	DSET_FLAG_BIT_MAP_SKBPRIO = 9,
	DSET_FLAG_MAP_SKBPRIO = (1 << DSET_FLAG_BIT_MAP_SKBPRIO),
	DSET_FLAG_BIT_MAP_SKBQUEUE = 10,
	DSET_FLAG_MAP_SKBQUEUE = (1 << DSET_FLAG_BIT_MAP_SKBQUEUE),
	DSET_FLAG_CMD_MAX = 15,
};

/* Flags at CADT attribute level, upper half of cmdattrs */
enum dset_cadt_flags
{
	DSET_FLAG_BIT_BEFORE = 0,
	DSET_FLAG_BEFORE = (1 << DSET_FLAG_BIT_BEFORE),
	DSET_FLAG_BIT_PHYSDEV = 1,
	DSET_FLAG_PHYSDEV = (1 << DSET_FLAG_BIT_PHYSDEV),
	DSET_FLAG_BIT_NOMATCH = 2,
	DSET_FLAG_NOMATCH = (1 << DSET_FLAG_BIT_NOMATCH),
	DSET_FLAG_BIT_WITH_COUNTERS = 3,
	DSET_FLAG_WITH_COUNTERS = (1 << DSET_FLAG_BIT_WITH_COUNTERS),
	DSET_FLAG_BIT_WITH_COMMENT = 4,
	DSET_FLAG_WITH_COMMENT = (1 << DSET_FLAG_BIT_WITH_COMMENT),
	DSET_FLAG_BIT_WITH_FORCEADD = 5,
	DSET_FLAG_WITH_FORCEADD = (1 << DSET_FLAG_BIT_WITH_FORCEADD),
	DSET_FLAG_BIT_WITH_SKBINFO = 6,
	DSET_FLAG_WITH_SKBINFO = (1 << DSET_FLAG_BIT_WITH_SKBINFO),
	DSET_FLAG_CADT_MAX = 15,
};

/* The flag bits which correspond to the non-extension create flags */
enum dset_create_flags
{
	DSET_CREATE_FLAG_BIT_FORCEADD = 0,
	DSET_CREATE_FLAG_FORCEADD = (1 << DSET_CREATE_FLAG_BIT_FORCEADD),
	DSET_CREATE_FLAG_BIT_MAX = 7,
};

/* Commands with settype-specific attributes */
enum dset_adt
{
	DSET_ADD,
	DSET_DEL,
	DSET_TEST,
	DSET_ADT_MAX,
	DSET_CREATE = DSET_ADT_MAX,
	DSET_CADT_MAX,
};

/* Sets are identified by an index in kernel space. Tweak with ip_set_id_t
 * and DSET_INVALID_ID if you want to increase the max number of sets.
 * Also, DSET_ATTR_INDEX must be changed.
 */
typedef __u16 domain_set_id_t;

#define DSET_INVALID_ID 65535

enum domain_set_dim
{
	DSET_DIM_ZERO = 0,
	DSET_DIM_ONE,
	DSET_DIM_TWO,
	DSET_DIM_THREE,
	/* Max dimension in elements.
	 * If changed, new revision of iptables match/target is required.
	 */
	DSET_DIM_MAX = 6,
	/* Backward compatibility: set match revision 2 */
	DSET_BIT_RETURN_NOMATCH = 7,
};

/* Option flags for kernel operations */
enum domain_set_kopt
{
	DSET_INV_MATCH = (1 << DSET_DIM_ZERO),
	DSET_DIM_ONE_SRC = (1 << DSET_DIM_ONE),
	DSET_DIM_TWO_SRC = (1 << DSET_DIM_TWO),
	DSET_DIM_THREE_SRC = (1 << DSET_DIM_THREE),
	DSET_RETURN_NOMATCH = (1 << DSET_BIT_RETURN_NOMATCH),
};

enum
{
	DSET_COUNTER_NONE = 0,
	DSET_COUNTER_EQ,
	DSET_COUNTER_NE,
	DSET_COUNTER_LT,
	DSET_COUNTER_GT,
};

/* Backward compatibility for set match v3 */
struct domain_set_counter_match0
{
	__u8 op;
	__u64 value;
};

struct domain_set_counter_match
{
	__u64 __attribute__((aligned(8))) value;
	__u8 op;
};

/* Interface to iptables/ip6tables */

#define SO_DOMAIN_SET 87

union domain_set_name_index {
	char name[DSET_MAXNAMELEN];
	domain_set_id_t index;
};

#define DOMAIN_SET_OP_GET_BYNAME 0x00000006 /* Get set index by name */
struct domain_set_req_get_set
{
	unsigned int op;
	unsigned int version;
	union domain_set_name_index set;
};

#define DOMAIN_SET_OP_GET_BYINDEX 0x00000007 /* Get set name by index */
/* Uses domain_set_req_get_set */

#define DOMAIN_SET_OP_GET_FNAME 0x00000008 /* Get set index and family */
struct domain_set_req_get_set_family
{
	unsigned int op;
	unsigned int version;
	unsigned int family;
	union domain_set_name_index set;
};

#define DOMAIN_SET_OP_VERSION 0x00000100 /* Ask kernel version */
struct domain_set_req_version
{
	unsigned int op;
	unsigned int version;
};

#endif /* _UAPI_DOMAIN_SET_H */
