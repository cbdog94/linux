/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef _DOMAIN_SET_H
#define _DOMAIN_SET_H

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/stringify.h>
#include <linux/vmalloc.h>
#include <net/netlink.h>
#include <linux/netfilter/dset/domain_set_compat.h>
#include <uapi/linux/netfilter/dset/domain_set.h>

#define _DOMAIN_SET_MODULE_DESC(a, b, c) \
	MODULE_DESCRIPTION(a " type of domain sets, revisions " b "-" c)
#define DOMAIN_SET_MODULE_DESC(a, b, c) \
	_DOMAIN_SET_MODULE_DESC(a, __stringify(b), __stringify(c))

/* Set features */
enum domain_set_feature
{
	DSET_TYPE_DOMAIN_FLAG = 0,
	DSET_TYPE_DOMAIN = (1 << DSET_TYPE_DOMAIN_FLAG),
	DSET_TYPE_NAME_FLAG = 1,
	DSET_TYPE_NAME = (1 << DSET_TYPE_NAME_FLAG),
	DSET_TYPE_NOMATCH_FLAG = 2,
	DSET_TYPE_NOMATCH = (1 << DSET_TYPE_NOMATCH_FLAG),
	/* Strictly speaking not a feature, but a flag for dumping:
	 * this settype must be dumped last */
	DSET_DUMP_LAST_FLAG = 3,
	DSET_DUMP_LAST = (1 << DSET_DUMP_LAST_FLAG),
};

/* Set extensions */
enum domain_set_extension
{
	DSET_EXT_BIT_TIMEOUT = 0,
	DSET_EXT_TIMEOUT = (1 << DSET_EXT_BIT_TIMEOUT),
	DSET_EXT_BIT_COUNTER = 1,
	DSET_EXT_COUNTER = (1 << DSET_EXT_BIT_COUNTER),
	DSET_EXT_BIT_COMMENT = 2,
	DSET_EXT_COMMENT = (1 << DSET_EXT_BIT_COMMENT),
	DSET_EXT_BIT_SKBINFO = 3,
	DSET_EXT_SKBINFO = (1 << DSET_EXT_BIT_SKBINFO),
	/* Mark set with an extension which needs to call destroy */
	DSET_EXT_BIT_DESTROY = 7,
	DSET_EXT_DESTROY = (1 << DSET_EXT_BIT_DESTROY),
};

#define SET_WITH_TIMEOUT(s) ((s)->extensions & DSET_EXT_TIMEOUT)
#define SET_WITH_COUNTER(s) ((s)->extensions & DSET_EXT_COUNTER)
#define SET_WITH_COMMENT(s) ((s)->extensions & DSET_EXT_COMMENT)
#define SET_WITH_SKBINFO(s) ((s)->extensions & DSET_EXT_SKBINFO)
#define SET_WITH_FORCEADD(s) ((s)->flags & DSET_CREATE_FLAG_FORCEADD)

/* Extension id, in size order */
enum domain_set_ext_id
{
	DSET_EXT_ID_COUNTER = 0,
	DSET_EXT_ID_TIMEOUT,
	DSET_EXT_ID_SKBINFO,
	DSET_EXT_ID_COMMENT,
	DSET_EXT_ID_MAX,
};

struct domain_set;

/* Extension type */
struct domain_set_ext_type
{
	/* Destroy extension private data (can be NULL) */
	void (*destroy)(struct domain_set *set, void *ext);
	enum domain_set_extension type;
	enum dset_cadt_flags flag;
	/* Size and minimal alignment */
	u8 len;
	u8 align;
};

extern const struct domain_set_ext_type domain_set_extensions[];

struct domain_set_counter
{
	atomic64_t bytes;
	atomic64_t packets;
};

struct domain_set_comment_rcu
{
	struct rcu_head rcu;
	char str[0];
};

struct domain_set_comment
{
	struct domain_set_comment_rcu __rcu *c;
};

struct domain_set_skbinfo
{
	u32 skbmark;
	u32 skbmarkmask;
	u32 skbprio;
	u16 skbqueue;
	u16 __pad;
};

struct domain_set_ext
{
	struct domain_set_skbinfo skbinfo;
	u64 packets;
	u64 bytes;
	char *comment;
	u32 timeout;
	u8 packets_op;
	u8 bytes_op;
};

struct domain_set;

#define ext_timeout(e, s) \
	((unsigned long *)(((void *)(e)) + (s)->offset[DSET_EXT_ID_TIMEOUT]))
#define ext_counter(e, s) \
	((struct domain_set_counter *)(((void *)(e)) + (s)->offset[DSET_EXT_ID_COUNTER]))
#define ext_comment(e, s) \
	((struct domain_set_comment *)(((void *)(e)) + (s)->offset[DSET_EXT_ID_COMMENT]))
#define ext_skbinfo(e, s) \
	((struct domain_set_skbinfo *)(((void *)(e)) + (s)->offset[DSET_EXT_ID_SKBINFO]))

typedef int (*dset_adtfn)(struct domain_set *set, void *value,
						  const struct domain_set_ext *ext,
						  struct domain_set_ext *mext, u32 cmdflags);

/* Kernel API function options */
struct domain_set_adt_opt
{
	u8 family;				   /* Actual protocol family */
	u8 dim;					   /* Dimension of match/target */
	u8 flags;				   /* Direction and negation flags */
	u32 cmdflags;			   /* Command-like flags */
	struct domain_set_ext ext; /* Extensions */
};

/* Set type, variant-specific part */
struct domain_set_type_variant
{
	/* Kernelspace: test/add/del entries
	 *		returns negative error code,
	 *			zero for no match/success to add/delete
	 *			positive for matching element */
	int (*kadt)(struct domain_set *set, const struct sk_buff *skb,
				const struct xt_action_param *par,
				enum dset_adt adt, struct domain_set_adt_opt *opt);

	/* Userspace: test/add/del entries
	 *		returns negative error code,
	 *			zero for no match/success to add/delete
	 *			positive for matching element */
	int (*uadt)(struct domain_set *set, struct nlattr *tb[],
				enum dset_adt adt, u32 *lineno, u32 flags, bool retried);

	/* Low level add/del/test functions */
	dset_adtfn adt[DSET_ADT_MAX];

	/* When adding entries and set is full, try to resize the set */
	int (*resize)(struct domain_set *set, bool retried);
	/* Destroy the set */
	void (*destroy)(struct domain_set *set);
	/* Flush the elements */
	void (*flush)(struct domain_set *set);
	/* Expire entries before listing */
	void (*expire)(struct domain_set *set);
	/* List set header data */
	int (*head)(struct domain_set *set, struct sk_buff *skb);
	/* List elements */
	int (*list)(const struct domain_set *set, struct sk_buff *skb,
				struct netlink_callback *cb);
	/* Keep listing private when resizing runs parallel */
	void (*uref)(struct domain_set *set, struct netlink_callback *cb,
				 bool start);

	/* Return true if "b" set is the same as "a"
	 * according to the create set parameters */
	bool (*same_set)(const struct domain_set *a, const struct domain_set *b);
};

/* The core set type structure */
struct domain_set_type
{
	struct list_head list;

	/* Typename */
	char name[DSET_MAXNAMELEN];
	/* Protocol version */
	u8 protocol;
	/* Set type dimension */
	u8 dimension;
	/*
	 * Supported family: may be NFPROTO_UNSPEC for both
	 * NFPROTO_IPV4/NFPROTO_IPV6.
	 */
	u8 family;
	/* Type revisions */
	u8 revision_min, revision_max;
	/* Set features to control swapping */
	u16 features;

	/* Create set */
	int (*create)(struct net *net, struct domain_set *set,
				  struct nlattr *tb[], u32 flags);

	/* Attribute policies */
	const struct nla_policy create_policy[DSET_ATTR_CREATE_MAX + 1];
	const struct nla_policy adt_policy[DSET_ATTR_ADT_MAX + 1];

	/* Set this to THIS_MODULE if you are a module, otherwise NULL */
	struct module *me;
};

/* register and unregister set type */
extern int domain_set_type_register(struct domain_set_type *set_type);
extern void domain_set_type_unregister(struct domain_set_type *set_type);

/* A generic domain set */
struct domain_set
{
	/* The name of the set */
	char name[DSET_MAXNAMELEN];
	/* Lock protecting the set data */
	spinlock_t lock;
	/* References to the set */
	u32 ref;
	/* References to the set for netlink events like dump,
	 * ref can be swapped out by domain_set_swap
	 */
	u32 ref_netlink;
	/* The core set type */
	struct domain_set_type *type;
	/* The type variant doing the real job */
	const struct domain_set_type_variant *variant;
	/* The actual INET family of the set */
	u8 family;
	/* The type revision */
	u8 revision;
	/* Extensions */
	u8 extensions;
	/* Create flags */
	u8 flags;
	/* Default timeout value, if enabled */
	u32 timeout;
	/* Number of elements (vs timeout) */
	u32 elements;
	/* Size of the dynamic extensions (vs timeout) */
	size_t ext_size;
	/* Element data size */
	size_t dsize;
	/* Offsets to extensions in elements */
	size_t offset[DSET_EXT_ID_MAX];
	/* The type specific data */
	void *data;
};

static inline void
domain_set_ext_destroy(struct domain_set *set, void *data)
{
	/* Check that the extension is enabled for the set and
	 * call it's destroy function for its extension part in data.
	 */
	if (SET_WITH_COMMENT(set))
	{
		struct domain_set_comment *c = ext_comment(data, set);

		domain_set_extensions[DSET_EXT_ID_COMMENT].destroy(set, c);
	}
}

int domain_set_put_flags(struct sk_buff *skb, struct domain_set *set);

/* Netlink CB args */
enum
{
	DSET_CB_NET = 0, /* net namespace */
	DSET_CB_PROTO,   /* dset protocol */
	DSET_CB_DUMP,	/* dump single set/all sets */
	DSET_CB_INDEX,   /* set index */
	DSET_CB_PRIVATE, /* set private data */
	DSET_CB_ARG0,	/* type specific */
};

/* register and unregister set references */
extern void domain_set_put_byindex(struct net *net, domain_set_id_t index);
extern void domain_set_name_byindex(struct net *net, domain_set_id_t index, char *name);
extern domain_set_id_t domain_set_nfnl_get_byindex(struct net *net, domain_set_id_t index);
extern void domain_set_nfnl_put(struct net *net, domain_set_id_t index);

/* API for iptables set match, and SET target */

extern int domain_set_test(domain_set_id_t id, const struct sk_buff *skb,
						   const struct xt_action_param *par,
						   struct domain_set_adt_opt *opt);

/* Utility functions */
extern void *domain_set_alloc(size_t size);
extern void domain_set_free(void *members);
extern size_t domain_set_elem_len(struct domain_set *set, struct nlattr *tb[],
								  size_t len, size_t align);
extern int domain_set_get_extensions(struct domain_set *set, struct nlattr *tb[],
									 struct domain_set_ext *ext);
extern int domain_set_put_extensions(struct sk_buff *skb, const struct domain_set *set,
									 const void *e, bool active);
extern bool domain_set_match_extensions(struct domain_set *set,
										const struct domain_set_ext *ext,
										struct domain_set_ext *mext,
										u32 flags, void *data);

/* Ignore DSET_ERR_EXIST errors if asked to do so? */
static inline bool
domain_set_eexist(int ret, u32 flags)
{
	return ret == -DSET_ERR_EXIST && (flags & DSET_FLAG_EXIST);
}

/* Match elements marked with nomatch */
static inline bool
domain_set_enomatch(int ret, u32 flags, enum dset_adt adt, struct domain_set *set)
{
	return adt == DSET_TEST &&
		   (set->type->features & DSET_TYPE_NOMATCH) &&
		   ((flags >> 16) & DSET_FLAG_NOMATCH) &&
		   (ret > 0 || ret == -ENOTEMPTY);
}

/* Check the NLA_F_NET_BYTEORDER flag */
static inline bool
domain_set_attr_netorder(struct nlattr *tb[], int type)
{
	return tb[type] && (tb[type]->nla_type & NLA_F_NET_BYTEORDER);
}

static inline bool
domain_set_optattr_netorder(struct nlattr *tb[], int type)
{
	return !tb[type] || (tb[type]->nla_type & NLA_F_NET_BYTEORDER);
}

/* Useful converters */
static inline u32
domain_set_get_h32(const struct nlattr *attr)
{
	return ntohl(nla_get_be32(attr));
}

static inline u16
domain_set_get_h16(const struct nlattr *attr)
{
	return ntohs(nla_get_be16(attr));
}

/* In order to support older kernels before patch ae0be8de9a53cda3:
 *
 * netlink: make nla_nest_start() add NLA_F_NESTED flag
 *
 * we have to keep  dset_nest_start() dset_nest_end()
 * in the package source
*/
#define dset_nest_start(skb, attr) nla_nest_start(skb, attr | NLA_F_NESTED)
#define dset_nest_end(skb, start) nla_nest_end(skb, start)

/* How often should the gc be run by default */
#define DSET_GC_TIME (3 * 60)

/* Timeout period depending on the timeout value of the given set */
#define DSET_GC_PERIOD(timeout) \
	((timeout / 3) ? min_t(u32, (timeout) / 3, DSET_GC_TIME) : 1)

/* Entry is set with no timeout value */
#define DSET_ELEM_PERMANENT 0

/* Set is defined with timeout support: timeout value may be 0 */
#define DSET_NO_TIMEOUT UINT_MAX

/* Max timeout value, see msecs_to_jiffies() in jiffies.h */
#define DSET_MAX_TIMEOUT (UINT_MAX >> 1) / MSEC_PER_SEC

#define domain_set_adt_opt_timeout(opt, set) \
	((opt)->ext.timeout != DSET_NO_TIMEOUT ? (opt)->ext.timeout : (set)->timeout)

static inline unsigned int
domain_set_timeout_uget(struct nlattr *tb)
{
	unsigned int timeout = domain_set_get_h32(tb);

	/* Normalize to fit into jiffies */
	if (timeout > DSET_MAX_TIMEOUT)
		timeout = DSET_MAX_TIMEOUT;

	return timeout;
}

static inline bool
domain_set_timeout_expired(const unsigned long *t)
{
	return *t != DSET_ELEM_PERMANENT && time_is_before_jiffies(*t);
}

static inline void
domain_set_timeout_set(unsigned long *timeout, u32 value)
{
	unsigned long t;

	if (!value)
	{
		*timeout = DSET_ELEM_PERMANENT;
		return;
	}

	t = msecs_to_jiffies(value * MSEC_PER_SEC) + jiffies;
	if (t == DSET_ELEM_PERMANENT)
		/* Bingo! :-) */
		t--;
	*timeout = t;
}

void domain_set_init_comment(struct domain_set *set, struct domain_set_comment *comment,
							 const struct domain_set_ext *ext);

static inline void
domain_set_init_counter(struct domain_set_counter *counter,
						const struct domain_set_ext *ext)
{
	if (ext->bytes != ULLONG_MAX)
		atomic64_set(&(counter)->bytes, (long long)(ext->bytes));
	if (ext->packets != ULLONG_MAX)
		atomic64_set(&(counter)->packets, (long long)(ext->packets));
}

static inline void
domain_set_init_skbinfo(struct domain_set_skbinfo *skbinfo,
						const struct domain_set_ext *ext)
{
	*skbinfo = ext->skbinfo;
}

#define DOMAIN_SET_INIT_KEXT(skb, opt, set)             \
	{                                                   \
		.bytes = (skb)->len, .packets = 1,              \
		.timeout = domain_set_adt_opt_timeout(opt, set) \
	}

#define DOMAIN_SET_INIT_UEXT(set)                   \
	{                                               \
		.bytes = ULLONG_MAX, .packets = ULLONG_MAX, \
		.timeout = (set)->timeout                   \
	}

#define DSET_CONCAT(a, b) a##b
#define DSET_TOKEN(a, b) DSET_CONCAT(a, b)

#endif /*_DOMAIN_SET_H */
