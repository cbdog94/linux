/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__DOMAIN_SET_HASH_H
#define _UAPI__DOMAIN_SET_HASH_H

#include <linux/netfilter/dset/domain_set.h>

/* Hash type specific error codes */
enum
{
	/* Hash is full */
	DSET_ERR_HASH_FULL = DSET_ERR_TYPE_SPECIFIC,
	/* Null-valued element */
	DSET_ERR_HASH_ELEM,
	/* Invalid protocol */
	DSET_ERR_INVALID_PROTO,
	/* Protocol missing but must be specified */
	DSET_ERR_MISSING_PROTO,
	/* Range not supported */
	DSET_ERR_HASH_RANGE_UNSUPPORTED,
	/* Invalid range */
	DSET_ERR_HASH_RANGE,
};

#endif /* _UAPI__DOMAIN_SET_HASH_H */
