/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _XT_DSET_H
#define _XT_DSET_H

#include <linux/types.h>
#include <linux/netfilter/dset/domain_set.h>

/* Revision 0 interface: backward compatible with netfilter/iptables */

/*
 * Option flags for kernel operations (xt_set_info_v0)
 */
#define DSET_SRC 0x01		/* Source match/add */
#define DSET_DST 0x02		/* Destination match/add */
#define DSET_MATCH_INV 0x04 /* Inverse matching */

struct xt_dset_info
{
	domain_set_id_t index;
	__u8 dim;
	__u8 flags;
};

/* Revision 0 match */

struct xt_dset_info_match_v0
{
	struct xt_dset_info match_set;
	struct domain_set_counter_match packets;
	struct domain_set_counter_match bytes;
	__u32 flags;
};

#endif /*_XT_DSET_H*/
