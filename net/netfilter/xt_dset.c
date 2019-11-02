/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* Kernel module which implements the set match and SET target
 * for netfilter/iptables.
 */

#include <linux/module.h>
#include <linux/skbuff.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/dset/domain_set.h>
#include <uapi/linux/netfilter/xt_dset.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bin Cheng <cbdog94@gmail.com>");
MODULE_DESCRIPTION("Xtables: domain set match");
MODULE_ALIAS("xt_DSET");
MODULE_ALIAS("ipt_dset");
MODULE_ALIAS("ebt_dset");
MODULE_ALIAS("ipt_DSET");
MODULE_ALIAS("ebt_DSET");

#ifdef HAVE_CHECKENTRY_BOOL
#define CHECK_OK 1
#define CHECK_FAIL(err) 0
#define CONST const
#define FTYPE bool
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35) */
#define CHECK_OK 0
#define CHECK_FAIL(err) (err)
#define CONST
#define FTYPE int
#endif
#ifdef HAVE_XT_MTCHK_PARAM_STRUCT_NET
#define XT_PAR_NET(par) ((par)->net)
#else
#define XT_PAR_NET(par) NULL
#endif

static inline int
match_dset(domain_set_id_t index, const struct sk_buff *skb,
		   const struct xt_action_param *par,
		   struct domain_set_adt_opt *opt, int inv)
{
	if (domain_set_test(index, skb, par, opt))
		inv = !inv;
	return inv;
}

#define ADT_OPT(n, f, d, fs, cfs, t, p, b, po, bo) \
	struct domain_set_adt_opt n = {                \
		.family = f,                               \
		.dim = d,                                  \
		.flags = fs,                               \
		.cmdflags = cfs,                           \
		.ext.timeout = t,                          \
		.ext.packets = p,                          \
		.ext.bytes = b,                            \
		.ext.packets_op = po,                      \
		.ext.bytes_op = bo,                        \
	}

/* Revision 0 interface: backward compatible with netfilter/iptables */

static FTYPE
dset_match_v0_checkentry(const struct xt_mtchk_param *par)
{
	struct xt_dset_info_match_v0 *info = par->matchinfo;
	domain_set_id_t index;

	index = domain_set_nfnl_get_byindex(XT_PAR_NET(par), info->match_set.index);

	if (index == DSET_INVALID_ID)
	{
		pr_warn("Cannot find set identified by id %u to match\n",
				info->match_set.index);
		return CHECK_FAIL(-ENOENT);
	}
	if (info->match_set.dim > DSET_DIM_MAX)
	{
		pr_warn("Protocol error: set match dimension is over the limit!\n");
		domain_set_nfnl_put(XT_PAR_NET(par), info->match_set.index);
		return CHECK_FAIL(-ERANGE);
	}

	return CHECK_OK;
}

static void
dset_match_v0_destroy(const struct xt_mtdtor_param *par)
{
	struct xt_dset_info_match_v0 *info = par->matchinfo;

	domain_set_nfnl_put(XT_PAR_NET(par), info->match_set.index);
}

static bool
dset_match_v0(const struct sk_buff *skb, CONST struct xt_action_param *par)
{
	const struct xt_dset_info_match_v0 *info = par->matchinfo;

	ADT_OPT(opt, XT_FAMILY(par), info->match_set.dim,
			info->match_set.flags, info->flags, UINT_MAX,
			info->packets.value, info->bytes.value,
			info->packets.op, info->bytes.op);

	if (info->packets.op != DSET_COUNTER_NONE ||
		info->bytes.op != DSET_COUNTER_NONE)
		opt.cmdflags |= DSET_FLAG_MATCH_COUNTERS;

	return match_dset(info->match_set.index, skb, par, &opt,
					  info->match_set.flags & DSET_INV_MATCH);
}

/* Revision 0 interface: backward compatible with netfilter/iptables */

#ifdef HAVE_XT_TARGET_PARAM
#undef xt_action_param
#define xt_action_param xt_target_param
#define CAST_TO_MATCH (const struct xt_match_param *)
#else
#define CAST_TO_MATCH
#endif

static struct xt_match set_matches[] __read_mostly = {
	{.name = "dset",
	 .family = NFPROTO_UNSPEC,
	 .revision = 0,
	 .match = dset_match_v0,
	 .matchsize = sizeof(struct xt_dset_info_match_v0),
	 .checkentry = dset_match_v0_checkentry,
	 .destroy = dset_match_v0_destroy,
	 .me = THIS_MODULE}};

static int __init xt_set_init(void)
{
	return xt_register_matches(set_matches, ARRAY_SIZE(set_matches));
}

static void __exit xt_set_fini(void)
{
	xt_unregister_matches(set_matches, ARRAY_SIZE(set_matches));
}

module_init(xt_set_init);
module_exit(xt_set_fini);
