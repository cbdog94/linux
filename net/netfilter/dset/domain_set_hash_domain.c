/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* Kernel module implementing an DOMAIN set type: the hash:domain type */

#include <linux/jhash.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <linux/random.h>
#include <net/netlink.h>
#include <net/tcp.h>

#include <linux/netfilter.h>
#include <linux/netfilter/dset/domain_set.h>
#include <linux/netfilter/dset/domain_set_hash.h>

#define DSET_TYPE_REV_MIN 0
/*				1	   Counters support */
/*				2	   Comments support */
/*				3	   Forceadd support */
#define DSET_TYPE_REV_MAX 4 /* skbinfo support  */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bin Cheng <cbdog94@gmail.com>");
DOMAIN_SET_MODULE_DESC("hash:domain", DSET_TYPE_REV_MIN, DSET_TYPE_REV_MAX);
MODULE_ALIAS("domain_set_hash:domain");

/* Type specific function prefix */
#define HTYPE hash_domain

/* Member elements */
struct hash_domain_elem
{
	char domain[DSET_MAX_DOMAIN_LEN];
};

/* Common functions */

static bool hash_domain_data_equal(const struct hash_domain_elem *e1,
								   const struct hash_domain_elem *e2,
								   u32 *multi)
{
	return strcmp(e1->domain, e2->domain) == 0;
}

static bool hash_domain_data_list(struct sk_buff *skb,
								  const struct hash_domain_elem *e)
{
	return nla_put(skb, DSET_ATTR_DOMAIN, DSET_MAX_DOMAIN_LEN, e->domain);
}

static void hash_domain_data_next(struct hash_domain_elem *next,
								  const struct hash_domain_elem *e)
{
	strncpy(next->domain, e->domain, DSET_MAX_DOMAIN_LEN);
}

#define MTYPE hash_domain

#define DOMAIN_SET_EMIT_CREATE
#define DOMAIN_SET_PROTO_UNDEF
#include "domain_set_hash_gen.h"

#define DOMAIN_OFFSET 40

static int hash_domain_kadt(struct domain_set *set, const struct sk_buff *skb,
							const struct xt_action_param *par,
							enum dset_adt adt, struct domain_set_adt_opt *opt)
{
	dset_adtfn adtfn = set->variant->adt[adt];
	struct hash_domain_elem e = {0};
	struct domain_set_ext ext = DOMAIN_SET_INIT_KEXT(skb, opt, set);
	char *domain = skb->data + DOMAIN_OFFSET;
	int label_length, total_length = 0, i, ret;
	char doamin_name[DSET_MAX_DOMAIN_LEN];
	while ((label_length = *domain) != 0)
	{
		if (total_length + label_length >= DSET_MAX_DOMAIN_LEN)
		{
			return 0;
		}
		strncpy(doamin_name + total_length, ++domain, label_length);
		total_length += label_length;
		*(doamin_name + total_length) = '.';
		total_length++;
		domain += label_length;
	}
	*(doamin_name + total_length - 1) = '\0';

	if (adt == DSET_TEST)
	{
		for (i = total_length - 1; i >= 0; i--)
		{
			if (*(doamin_name + i) == '.')
			{
				strncpy(e.domain, doamin_name + i + 1,
						total_length - i - 1);
				ret = adtfn(set, &e, &ext, &opt->ext,
							opt->cmdflags);
				if (ret != 0)
				{
					return ret;
				}
			}
		}
		strncpy(e.domain, doamin_name + i + 1, total_length - i - 1);
		return adtfn(set, &e, &ext, &opt->ext, opt->cmdflags);
	}
	else
	{
		strncpy(e.domain, doamin_name, DSET_MAX_DOMAIN_LEN);
		return adtfn(set, &e, &ext, &opt->ext, opt->cmdflags);
	}
}

static int hash_domain_uadt(struct domain_set *set, struct nlattr *tb[],
							enum dset_adt adt, u32 *lineno, u32 flags,
							bool retried)
{
	dset_adtfn adtfn = set->variant->adt[adt];
	struct hash_domain_elem e = {0};
	struct domain_set_ext ext = DOMAIN_SET_INIT_UEXT(set);
	int ret = 0;

	if (tb[DSET_ATTR_LINENO])
		*lineno = nla_get_u32(tb[DSET_ATTR_LINENO]);

	if (unlikely(!tb[DSET_ATTR_DOMAIN]))
		return -DSET_ERR_PROTOCOL;

	nla_strlcpy(e.domain, tb[DSET_ATTR_DOMAIN], DSET_MAX_DOMAIN_LEN);
	ret = domain_set_get_extensions(set, tb, &ext);

	if (ret)
		return ret;

	if (adt == DSET_TEST)
		return adtfn(set, &e, &ext, &ext, flags);

	ret = adtfn(set, &e, &ext, &ext, flags);

	if (ret && !domain_set_eexist(ret, flags))
		return ret;

	return ret;
}

static struct domain_set_type hash_domain_type __read_mostly = {
	.name = "hash:domain",
	.protocol = DSET_PROTOCOL,
	.features = DSET_TYPE_DOMAIN,
	.dimension = DSET_DIM_ONE,
	.family = NFPROTO_UNSPEC,
	.revision_min = DSET_TYPE_REV_MIN,
	.revision_max = DSET_TYPE_REV_MAX,
	.create = hash_domain_create,
	.create_policy =
		{
			[DSET_ATTR_HASHSIZE] = {.type = NLA_U32},
			[DSET_ATTR_MAXELEM] = {.type = NLA_U32},
			[DSET_ATTR_PROBES] = {.type = NLA_U8},
			[DSET_ATTR_RESIZE] = {.type = NLA_U8},
			[DSET_ATTR_TIMEOUT] = {.type = NLA_U32},
			[DSET_ATTR_CADT_FLAGS] = {.type = NLA_U32},
		},
	.adt_policy =
		{
			[DSET_ATTR_DOMAIN] = {.type = NLA_NUL_STRING,
								  .len = DSET_MAX_DOMAIN_LEN},
			[DSET_ATTR_TIMEOUT] = {.type = NLA_U32},
			[DSET_ATTR_LINENO] = {.type = NLA_U32},
			[DSET_ATTR_BYTES] = {.type = NLA_U64},
			[DSET_ATTR_PACKETS] = {.type = NLA_U64},
			[DSET_ATTR_COMMENT] = {.type = NLA_NUL_STRING,
								   .len = DSET_MAX_COMMENT_SIZE},
			[DSET_ATTR_SKBMARK] = {.type = NLA_U64},
			[DSET_ATTR_SKBPRIO] = {.type = NLA_U32},
			[DSET_ATTR_SKBQUEUE] = {.type = NLA_U16},
		},
	.me = THIS_MODULE,
};

static int __init hash_domain_init(void)
{
	return domain_set_type_register(&hash_domain_type);
}

static void __exit hash_domain_fini(void)
{
	rcu_barrier();
	domain_set_type_unregister(&hash_domain_type);
}

module_init(hash_domain_init);
module_exit(hash_domain_fini);
