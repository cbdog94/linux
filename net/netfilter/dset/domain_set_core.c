/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* Kernel module for DOMAIN set management */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/rculist.h>
#include <net/netlink.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/dset/domain_set.h>

static LIST_HEAD(domain_set_type_list); /* all registered set types */
static DEFINE_MUTEX(domain_set_type_mutex); /* protects domain_set_type_list */
static DEFINE_RWLOCK(domain_set_ref_lock); /* protects the set refs */

struct domain_set_net {
	struct domain_set *__rcu *domain_set_list; /* all individual sets */
	domain_set_id_t domain_set_max; /* max number of sets */
	bool is_deleted; /* deleted by domain_set_net_exit */
	bool is_destroyed; /* all sets are destroyed */
};

static unsigned int domain_set_net_id __read_mostly;

static struct domain_set_net *domain_set_pernet(struct net *net)
{
	return net_generic(net, domain_set_net_id);
}

#define DOMAIN_SET_INC 64
#define STRNCMP(a, b) (strncmp(a, b, DSET_MAXNAMELEN) == 0)

static unsigned int max_sets;

module_param(max_sets, int, 0600);
MODULE_PARM_DESC(max_sets, "maximal number of sets");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bin Cheng <cbdog94@gmail.com>");
MODULE_DESCRIPTION("domain_set: protocol " __stringify(DSET_PROTOCOL));
MODULE_ALIAS_NFNL_SUBSYS(NFNL_SUBSYS_DSET);

/* When the nfnl mutex or domain_set_ref_lock is held: */
#define domain_set_dereference(p)                                              \
	rcu_dereference_protected(                                             \
		p, lockdep_nfnl_is_held(NFNL_SUBSYS_DSET) ||                   \
			   lockdep_is_held(&domain_set_ref_lock))
#define domain_set(inst, id) domain_set_dereference((inst)->domain_set_list)[id]
#define domain_set_ref_netlink(inst, id)                                       \
	rcu_dereference_raw((inst)->domain_set_list)[id]

/* The set types are implemented in modules and registered set types
 * can be found in domain_set_type_list. Adding/deleting types is
 * serialized by domain_set_type_mutex.
 */

static void domain_set_type_lock(void)
{
	mutex_lock(&domain_set_type_mutex);
}

static void domain_set_type_unlock(void)
{
	mutex_unlock(&domain_set_type_mutex);
}

/* Register and deregister settype */

static struct domain_set_type *find_set_type(const char *name, u8 family,
					     u8 revision)
{
	struct domain_set_type *type;

	list_for_each_entry_rcu (type, &domain_set_type_list, list)
		if (STRNCMP(type->name, name) &&
		    (type->family == family ||
		     type->family == NFPROTO_UNSPEC) &&
		    revision >= type->revision_min &&
		    revision <= type->revision_max)
			return type;
	return NULL;
}

/* Unlock, try to load a set type module and lock again */
static bool load_settype(const char *name)
{
	nfnl_unlock(NFNL_SUBSYS_DSET);
	pr_debug("try to load domain_set_%s\n", name);
	if (request_module("domain_set_%s", name) < 0) {
		pr_warn("Can't find domain_set type %s\n", name);
		nfnl_lock(NFNL_SUBSYS_DSET);
		return false;
	}
	nfnl_lock(NFNL_SUBSYS_DSET);
	return true;
}

/* Find a set type and reference it */
#define find_set_type_get(name, family, revision, found)                       \
	__find_set_type_get(name, family, revision, found, false)

static int __find_set_type_get(const char *name, u8 family, u8 revision,
			       struct domain_set_type **found, bool retry)
{
	struct domain_set_type *type;
	int err;

	if (retry && !load_settype(name))
		return -DSET_ERR_FIND_TYPE;

	rcu_read_lock();
	*found = find_set_type(name, family, revision);
	if (*found) {
		err = !try_module_get((*found)->me) ? -EFAULT : 0;
		goto unlock;
	}
	/* Make sure the type is already loaded
	 * but we don't support the revision
	 */
	list_for_each_entry_rcu (type, &domain_set_type_list, list)
		if (STRNCMP(type->name, name)) {
			err = -DSET_ERR_FIND_TYPE;
			goto unlock;
		}
	rcu_read_unlock();

	return retry ? -DSET_ERR_FIND_TYPE :
		       __find_set_type_get(name, family, revision, found, true);

unlock:
	rcu_read_unlock();
	return err;
}

/* Find a given set type by name and family.
 * If we succeeded, the supported minimal and maximum revisions are
 * filled out.
 */
#define find_set_type_minmax(name, family, min, max)                           \
	__find_set_type_minmax(name, family, min, max, false)

static int __find_set_type_minmax(const char *name, u8 family, u8 *min, u8 *max,
				  bool retry)
{
	struct domain_set_type *type;
	bool found = false;

	if (retry && !load_settype(name))
		return -DSET_ERR_FIND_TYPE;

	*min = 255;
	*max = 0;
	rcu_read_lock();
	list_for_each_entry_rcu (type, &domain_set_type_list, list)
		if (STRNCMP(type->name, name) &&
		    (type->family == family ||
		     type->family == NFPROTO_UNSPEC)) {
			found = true;
			if (type->revision_min < *min)
				*min = type->revision_min;
			if (type->revision_max > *max)
				*max = type->revision_max;
		}
	rcu_read_unlock();
	if (found)
		return 0;

	return retry ? -DSET_ERR_FIND_TYPE :
		       __find_set_type_minmax(name, family, min, max, true);
}

#define family_name(f)                                                         \
	((f) == NFPROTO_IPV4 ? "inet" : (f) == NFPROTO_IPV6 ? "inet6" : "any")

/* Register a set type structure. The type is identified by
 * the unique triple of name, family and revision.
 */
int domain_set_type_register(struct domain_set_type *type)
{
	int ret = 0;

	if (type->protocol != DSET_PROTOCOL) {
		pr_warn("domain_set type %s, family %s, revision %u:%u uses wrong protocol version %u (want %u)\n",
			type->name, family_name(type->family),
			type->revision_min, type->revision_max, type->protocol,
			DSET_PROTOCOL);
		return -EINVAL;
	}

	domain_set_type_lock();
	if (find_set_type(type->name, type->family, type->revision_min)) {
		/* Duplicate! */
		pr_warn("domain_set type %s, family %s with revision min %u already registered!\n",
			type->name, family_name(type->family),
			type->revision_min);
		domain_set_type_unlock();
		return -EINVAL;
	}
	list_add_rcu(&type->list, &domain_set_type_list);
	pr_debug("type %s, family %s, revision %u:%u registered.\n", type->name,
		 family_name(type->family), type->revision_min,
		 type->revision_max);
	domain_set_type_unlock();

	return ret;
}
EXPORT_SYMBOL_GPL(domain_set_type_register);

/* Unregister a set type. There's a small race with domain_set_create */
void domain_set_type_unregister(struct domain_set_type *type)
{
	domain_set_type_lock();
	if (!find_set_type(type->name, type->family, type->revision_min)) {
		pr_warn("domain_set type %s, family %s with revision min %u not registered\n",
			type->name, family_name(type->family),
			type->revision_min);
		domain_set_type_unlock();
		return;
	}
	list_del_rcu(&type->list);
	pr_debug("type %s, family %s with revision min %u unregistered.\n",
		 type->name, family_name(type->family), type->revision_min);
	domain_set_type_unlock();

	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(domain_set_type_unregister);

/* Utility functions */
void *domain_set_alloc(size_t size)
{
	void *members = NULL;

	if (size < KMALLOC_MAX_SIZE)
		members = kzalloc(size, GFP_KERNEL | __GFP_NOWARN);

	if (members) {
		pr_debug("%p: allocated with kmalloc\n", members);
		return members;
	}

	members = vzalloc(size);
	if (!members)
		return NULL;
	pr_debug("%p: allocated with vmalloc\n", members);

	return members;
}
EXPORT_SYMBOL_GPL(domain_set_alloc);

void domain_set_free(void *members)
{
	pr_debug("%p: free with %s\n", members,
		 is_vmalloc_addr(members) ? "vfree" : "kfree");
	kvfree(members);
}
EXPORT_SYMBOL_GPL(domain_set_free);

static bool flag_nested(const struct nlattr *nla)
{
	return nla->nla_type & NLA_F_NESTED;
}

static u32 domain_set_timeout_get(const unsigned long *timeout)
{
	u32 t;

	if (*timeout == DSET_ELEM_PERMANENT)
		return 0;

	t = jiffies_to_msecs(*timeout - jiffies) / MSEC_PER_SEC;
	/* Zero value in userspace means no timeout */
	return t == 0 ? 1 : t;
}

static char *domain_set_comment_uget(struct nlattr *tb)
{
	return nla_data(tb);
}

/* Called from uadd only, protected by the set spinlock.
 * The kadt functions don't use the comment extensions in any way.
 */
void domain_set_init_comment(struct domain_set *set,
			     struct domain_set_comment *comment,
			     const struct domain_set_ext *ext)
{
	struct domain_set_comment_rcu *c =
		rcu_dereference_protected(comment->c, 1);
	size_t len = ext->comment ? strlen(ext->comment) : 0;

	if (unlikely(c)) {
		set->ext_size -= sizeof(*c) + strlen(c->str) + 1;
		kfree_rcu(c, rcu);
		rcu_assign_pointer(comment->c, NULL);
	}
	if (!len)
		return;
	if (unlikely(len > DSET_MAX_COMMENT_SIZE))
		len = DSET_MAX_COMMENT_SIZE;
	c = kmalloc(sizeof(*c) + len + 1, GFP_ATOMIC);
	if (unlikely(!c))
		return;
	strlcpy(c->str, ext->comment, len + 1);
	set->ext_size += sizeof(*c) + strlen(c->str) + 1;
	rcu_assign_pointer(comment->c, c);
}
EXPORT_SYMBOL_GPL(domain_set_init_comment);

/* Used only when dumping a set, protected by rcu_read_lock() */
static int domain_set_put_comment(struct sk_buff *skb,
				  const struct domain_set_comment *comment)
{
	struct domain_set_comment_rcu *c = rcu_dereference(comment->c);

	if (!c)
		return 0;
	return nla_put_string(skb, DSET_ATTR_COMMENT, c->str);
}

/* Called from uadd/udel, flush or the garbage collectors protected
 * by the set spinlock.
 * Called when the set is destroyed and when there can't be any user
 * of the set data anymore.
 */
static void domain_set_comment_free(struct domain_set *set, void *ptr)
{
	struct domain_set_comment *comment = ptr;
	struct domain_set_comment_rcu *c;

	c = rcu_dereference_protected(comment->c, 1);
	if (unlikely(!c))
		return;
	set->ext_size -= sizeof(*c) + strlen(c->str) + 1;
	kfree_rcu(c, rcu);
	rcu_assign_pointer(comment->c, NULL);
}

typedef void (*destroyer)(struct domain_set *, void *);
/* dset data extension types, in size order */

const struct domain_set_ext_type domain_set_extensions[] = {
	[DSET_EXT_ID_COUNTER] =
		{
			.type = DSET_EXT_COUNTER,
			.flag = DSET_FLAG_WITH_COUNTERS,
			.len = sizeof(struct domain_set_counter),
			.align = __alignof__(struct domain_set_counter),
		},
	[DSET_EXT_ID_TIMEOUT] =
		{
			.type = DSET_EXT_TIMEOUT,
			.len = sizeof(unsigned long),
			.align = __alignof__(unsigned long),
		},
	[DSET_EXT_ID_SKBINFO] =
		{
			.type = DSET_EXT_SKBINFO,
			.flag = DSET_FLAG_WITH_SKBINFO,
			.len = sizeof(struct domain_set_skbinfo),
			.align = __alignof__(struct domain_set_skbinfo),
		},
	[DSET_EXT_ID_COMMENT] =
		{
			.type = DSET_EXT_COMMENT | DSET_EXT_DESTROY,
			.flag = DSET_FLAG_WITH_COMMENT,
			.len = sizeof(struct domain_set_comment),
			.align = __alignof__(struct domain_set_comment),
			.destroy = domain_set_comment_free,
		},
};
EXPORT_SYMBOL_GPL(domain_set_extensions);

static bool add_extension(enum domain_set_ext_id id, u32 flags,
			  struct nlattr *tb[])
{
	return domain_set_extensions[id].flag ?
		       (flags & domain_set_extensions[id].flag) :
		       !!tb[DSET_ATTR_TIMEOUT];
}

size_t domain_set_elem_len(struct domain_set *set, struct nlattr *tb[],
			   size_t len, size_t align)
{
	enum domain_set_ext_id id;
	u32 cadt_flags = 0;

	if (tb[DSET_ATTR_CADT_FLAGS])
		cadt_flags = domain_set_get_h32(tb[DSET_ATTR_CADT_FLAGS]);
	if (cadt_flags & DSET_FLAG_WITH_FORCEADD)
		set->flags |= DSET_CREATE_FLAG_FORCEADD;
	if (!align)
		align = 1;
	for (id = 0; id < DSET_EXT_ID_MAX; id++) {
		if (!add_extension(id, cadt_flags, tb))
			continue;
		len = ALIGN(len, domain_set_extensions[id].align);
		set->offset[id] = len;
		set->extensions |= domain_set_extensions[id].type;
		len += domain_set_extensions[id].len;
	}
	return ALIGN(len, align);
}
EXPORT_SYMBOL_GPL(domain_set_elem_len);

int domain_set_get_extensions(struct domain_set *set, struct nlattr *tb[],
			      struct domain_set_ext *ext)
{
	u64 fullmark;

	if (unlikely(!domain_set_optattr_netorder(tb, DSET_ATTR_TIMEOUT) ||
		     !domain_set_optattr_netorder(tb, DSET_ATTR_PACKETS) ||
		     !domain_set_optattr_netorder(tb, DSET_ATTR_BYTES) ||
		     !domain_set_optattr_netorder(tb, DSET_ATTR_SKBMARK) ||
		     !domain_set_optattr_netorder(tb, DSET_ATTR_SKBPRIO) ||
		     !domain_set_optattr_netorder(tb, DSET_ATTR_SKBQUEUE)))
		return -DSET_ERR_PROTOCOL;

	if (tb[DSET_ATTR_TIMEOUT]) {
		if (!SET_WITH_TIMEOUT(set))
			return -DSET_ERR_TIMEOUT;
		ext->timeout = domain_set_timeout_uget(tb[DSET_ATTR_TIMEOUT]);
	}
	if (tb[DSET_ATTR_BYTES] || tb[DSET_ATTR_PACKETS]) {
		if (!SET_WITH_COUNTER(set))
			return -DSET_ERR_COUNTER;
		if (tb[DSET_ATTR_BYTES])
			ext->bytes =
				be64_to_cpu(nla_get_be64(tb[DSET_ATTR_BYTES]));
		if (tb[DSET_ATTR_PACKETS])
			ext->packets = be64_to_cpu(
				nla_get_be64(tb[DSET_ATTR_PACKETS]));
	}
	if (tb[DSET_ATTR_COMMENT]) {
		if (!SET_WITH_COMMENT(set))
			return -DSET_ERR_COMMENT;
		ext->comment = domain_set_comment_uget(tb[DSET_ATTR_COMMENT]);
	}
	if (tb[DSET_ATTR_SKBMARK]) {
		if (!SET_WITH_SKBINFO(set))
			return -DSET_ERR_SKBINFO;
		fullmark = be64_to_cpu(nla_get_be64(tb[DSET_ATTR_SKBMARK]));
		ext->skbinfo.skbmark = fullmark >> 32;
		ext->skbinfo.skbmarkmask = fullmark & 0xffffffff;
	}
	if (tb[DSET_ATTR_SKBPRIO]) {
		if (!SET_WITH_SKBINFO(set))
			return -DSET_ERR_SKBINFO;
		ext->skbinfo.skbprio =
			be32_to_cpu(nla_get_be32(tb[DSET_ATTR_SKBPRIO]));
	}
	if (tb[DSET_ATTR_SKBQUEUE]) {
		if (!SET_WITH_SKBINFO(set))
			return -DSET_ERR_SKBINFO;
		ext->skbinfo.skbqueue =
			be16_to_cpu(nla_get_be16(tb[DSET_ATTR_SKBQUEUE]));
	}
	return 0;
}
EXPORT_SYMBOL_GPL(domain_set_get_extensions);

static u64 domain_set_get_bytes(const struct domain_set_counter *counter)
{
	return (u64)atomic64_read(&(counter)->bytes);
}

static u64 domain_set_get_packets(const struct domain_set_counter *counter)
{
	return (u64)atomic64_read(&(counter)->packets);
}

static bool domain_set_put_counter(struct sk_buff *skb,
				   const struct domain_set_counter *counter)
{
	return DSET_NLA_PUT_NET64(skb, DSET_ATTR_BYTES,
				  cpu_to_be64(domain_set_get_bytes(counter)),
				  DSET_ATTR_PAD) ||
	       DSET_NLA_PUT_NET64(skb, DSET_ATTR_PACKETS,
				  cpu_to_be64(domain_set_get_packets(counter)),
				  DSET_ATTR_PAD);
}

static bool domain_set_put_skbinfo(struct sk_buff *skb,
				   const struct domain_set_skbinfo *skbinfo)
{
	/* Send nonzero parameters only */
	return ((skbinfo->skbmark || skbinfo->skbmarkmask) &&
		DSET_NLA_PUT_NET64(skb, DSET_ATTR_SKBMARK,
				   cpu_to_be64((u64)skbinfo->skbmark << 32 |
					       skbinfo->skbmarkmask),
				   DSET_ATTR_PAD)) ||
	       (skbinfo->skbprio &&
		nla_put_net32(skb, DSET_ATTR_SKBPRIO,
			      cpu_to_be32(skbinfo->skbprio))) ||
	       (skbinfo->skbqueue &&
		nla_put_net16(skb, DSET_ATTR_SKBQUEUE,
			      cpu_to_be16(skbinfo->skbqueue)));
}

int domain_set_put_extensions(struct sk_buff *skb, const struct domain_set *set,
			      const void *e, bool active)
{
	if (SET_WITH_TIMEOUT(set)) {
		unsigned long *timeout = ext_timeout(e, set);

		if (nla_put_net32(
			    skb, DSET_ATTR_TIMEOUT,
			    htonl(active ? domain_set_timeout_get(timeout) :
					   *timeout)))
			return -EMSGSIZE;
	}
	if (SET_WITH_COUNTER(set) &&
	    domain_set_put_counter(skb, ext_counter(e, set)))
		return -EMSGSIZE;
	if (SET_WITH_COMMENT(set) &&
	    domain_set_put_comment(skb, ext_comment(e, set)))
		return -EMSGSIZE;
	if (SET_WITH_SKBINFO(set) &&
	    domain_set_put_skbinfo(skb, ext_skbinfo(e, set)))
		return -EMSGSIZE;
	return 0;
}
EXPORT_SYMBOL_GPL(domain_set_put_extensions);

static bool domain_set_match_counter(u64 counter, u64 match, u8 op)
{
	switch (op) {
	case DSET_COUNTER_NONE:
		return true;
	case DSET_COUNTER_EQ:
		return counter == match;
	case DSET_COUNTER_NE:
		return counter != match;
	case DSET_COUNTER_LT:
		return counter < match;
	case DSET_COUNTER_GT:
		return counter > match;
	}
	return false;
}

static void domain_set_add_bytes(u64 bytes, struct domain_set_counter *counter)
{
	atomic64_add((long long)bytes, &(counter)->bytes);
}

static void domain_set_add_packets(u64 packets,
				   struct domain_set_counter *counter)
{
	atomic64_add((long long)packets, &(counter)->packets);
}

static void domain_set_update_counter(struct domain_set_counter *counter,
				      const struct domain_set_ext *ext,
				      u32 flags)
{
	if (ext->packets != ULLONG_MAX &&
	    !(flags & DSET_FLAG_SKIP_COUNTER_UPDATE)) {
		domain_set_add_bytes(ext->bytes, counter);
		domain_set_add_packets(ext->packets, counter);
	}
}

static void domain_set_get_skbinfo(struct domain_set_skbinfo *skbinfo,
				   const struct domain_set_ext *ext,
				   struct domain_set_ext *mext, u32 flags)
{
	mext->skbinfo = *skbinfo;
}

bool domain_set_match_extensions(struct domain_set *set,
				 const struct domain_set_ext *ext,
				 struct domain_set_ext *mext, u32 flags,
				 void *data)
{
	if (SET_WITH_TIMEOUT(set) &&
	    domain_set_timeout_expired(ext_timeout(data, set)))
		return false;
	if (SET_WITH_COUNTER(set)) {
		struct domain_set_counter *counter = ext_counter(data, set);

		if (flags & DSET_FLAG_MATCH_COUNTERS &&
		    !(domain_set_match_counter(domain_set_get_packets(counter),
					       mext->packets,
					       mext->packets_op) &&
		      domain_set_match_counter(domain_set_get_bytes(counter),
					       mext->bytes, mext->bytes_op)))
			return false;
		domain_set_update_counter(counter, ext, flags);
	}
	if (SET_WITH_SKBINFO(set))
		domain_set_get_skbinfo(ext_skbinfo(data, set), ext, mext,
				       flags);
	return true;
}
EXPORT_SYMBOL_GPL(domain_set_match_extensions);

/* Creating/destroying/renaming/swapping affect the existence and
 * the properties of a set. All of these can be executed from userspace
 * only and serialized by the nfnl mutex indirectly from nfnetlink.
 *
 * Sets are identified by their index in domain_set_list and the index
 * is used by the external references (set/SET netfilter modules).
 *
 * The set behind an index may change by swapping only, from userspace.
 */

static void __domain_set_get(struct domain_set *set)
{
	write_lock_bh(&domain_set_ref_lock);
	set->ref++;
	write_unlock_bh(&domain_set_ref_lock);
}

static void __domain_set_put(struct domain_set *set)
{
	write_lock_bh(&domain_set_ref_lock);
	BUG_ON(set->ref == 0);
	set->ref--;
	write_unlock_bh(&domain_set_ref_lock);
}

/* set->ref can be swapped out by domain_set_swap, netlink events (like dump) need
 * a separate reference counter
 */
static void __domain_set_put_netlink(struct domain_set *set)
{
	write_lock_bh(&domain_set_ref_lock);
	BUG_ON(set->ref_netlink == 0);
	set->ref_netlink--;
	write_unlock_bh(&domain_set_ref_lock);
}

/* Add, del and test set entries from kernel.
 *
 * The set behind the index must exist and must be referenced
 * so it can't be destroyed (or changed) under our foot.
 */

static struct domain_set *domain_set_rcu_get(struct net *net,
					     domain_set_id_t index)
{
	struct domain_set *set;
	struct domain_set_net *inst = domain_set_pernet(net);

	rcu_read_lock();
	/* domain_set_list itself needs to be protected */
	set = rcu_dereference(inst->domain_set_list)[index];
	rcu_read_unlock();

	return set;
}

int domain_set_test(domain_set_id_t index, const struct sk_buff *skb,
		    const struct xt_action_param *par,
		    struct domain_set_adt_opt *opt)
{
	struct domain_set *set = domain_set_rcu_get(DSET_DEV_NET(par), index);
	int ret = 0;

	BUG_ON(!set);
	pr_debug("set %s, index %u\n", set->name, index);

	if (!(opt->family == set->family || set->family == NFPROTO_UNSPEC))
		return 0;

	rcu_read_lock_bh();
	ret = set->variant->kadt(set, skb, par, DSET_TEST, opt);
	rcu_read_unlock_bh();

	if (ret == -EAGAIN) {
		/* Type requests element to be completed */
		pr_debug("element must be completed, ADD is triggered\n");
		spin_lock_bh(&set->lock);
		set->variant->kadt(set, skb, par, DSET_ADD, opt);
		spin_unlock_bh(&set->lock);
		ret = 1;
	} else {
		/* --return-nomatch: invert matched element */
		if ((opt->cmdflags & DSET_FLAG_RETURN_NOMATCH) &&
		    (set->type->features & DSET_TYPE_NOMATCH) &&
		    (ret > 0 || ret == -ENOTEMPTY))
			ret = -ret;
	}

	/* Convert error codes to nomatch */
	return (ret < 0 ? 0 : ret);
}
EXPORT_SYMBOL_GPL(domain_set_test);

/* Find set by index, reference it once. The reference makes sure the
 * thing pointed to, does not go away under our feet.
 *
 * The nfnl mutex is used in the function.
 */
domain_set_id_t domain_set_nfnl_get_byindex(struct net *net,
					    domain_set_id_t index)
{
	struct domain_set *set;
	struct domain_set_net *inst = domain_set_pernet(net);

	if (index >= inst->domain_set_max)
		return DSET_INVALID_ID;

	nfnl_lock(NFNL_SUBSYS_DSET);
	set = domain_set(inst, index);
	if (set)
		__domain_set_get(set);
	else
		index = DSET_INVALID_ID;
	nfnl_unlock(NFNL_SUBSYS_DSET);

	return index;
}
EXPORT_SYMBOL_GPL(domain_set_nfnl_get_byindex);

/* If the given set pointer points to a valid set, decrement
 * reference count by 1. The caller shall not assume the index
 * to be valid, after calling this function.
 *
 * The nfnl mutex is used in the function.
 */
void domain_set_nfnl_put(struct net *net, domain_set_id_t index)
{
	struct domain_set *set;
	struct domain_set_net *inst = domain_set_pernet(net);

	nfnl_lock(NFNL_SUBSYS_DSET);
	if (!inst->is_deleted) { /* already deleted from domain_set_net_exit() */
		set = domain_set(inst, index);
		if (set)
			__domain_set_put(set);
	}
	nfnl_unlock(NFNL_SUBSYS_DSET);
}
EXPORT_SYMBOL_GPL(domain_set_nfnl_put);

/* Communication protocol with userspace over netlink.
 *
 * The commands are serialized by the nfnl mutex.
 */

static inline u8 protocol(const struct nlattr *const tb[])
{
	return nla_get_u8(tb[DSET_ATTR_PROTOCOL]);
}

static inline bool protocol_failed(const struct nlattr *const tb[])
{
	return !tb[DSET_ATTR_PROTOCOL] || protocol(tb) != DSET_PROTOCOL;
}

static inline bool protocol_min_failed(const struct nlattr *const tb[])
{
	return !tb[DSET_ATTR_PROTOCOL] || protocol(tb) < DSET_PROTOCOL_MIN;
}

static inline u32 flag_exist(const struct nlmsghdr *nlh)
{
	return nlh->nlmsg_flags & NLM_F_EXCL ? 0 : DSET_FLAG_EXIST;
}

static struct nlmsghdr *start_msg(struct sk_buff *skb, u32 portid, u32 seq,
				  unsigned int flags, enum dset_cmd cmd)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfmsg;

	nlh = nlmsg_put(skb, portid, seq, nfnl_msg_type(NFNL_SUBSYS_DSET, cmd),
			sizeof(*nfmsg), flags);
	if (!nlh)
		return NULL;

	nfmsg = nlmsg_data(nlh);
	nfmsg->nfgen_family = NFPROTO_UNSPEC;
	nfmsg->version = NFNETLINK_V0;
	nfmsg->res_id = 0;

	return nlh;
}

/* Create a set */

static const struct nla_policy domain_set_create_policy[DSET_ATTR_CMD_MAX + 1] =
	{
		[DSET_ATTR_PROTOCOL] = { .type = NLA_U8 },
		[DSET_ATTR_SETNAME] = { .type = NLA_NUL_STRING,
					.len = DSET_MAXNAMELEN - 1 },
		[DSET_ATTR_TYPENAME] = { .type = NLA_NUL_STRING,
					 .len = DSET_MAXNAMELEN - 1 },
		[DSET_ATTR_REVISION] = { .type = NLA_U8 },
		[DSET_ATTR_FAMILY] = { .type = NLA_U8 },
		[DSET_ATTR_DATA] = { .type = NLA_NESTED },
	};

static struct domain_set *find_set_and_id(struct domain_set_net *inst,
					  const char *name, domain_set_id_t *id)
{
	struct domain_set *set = NULL;
	domain_set_id_t i;

	*id = DSET_INVALID_ID;
	for (i = 0; i < inst->domain_set_max; i++) {
		set = domain_set(inst, i);
		if (set && STRNCMP(set->name, name)) {
			*id = i;
			break;
		}
	}
	return (*id == DSET_INVALID_ID ? NULL : set);
}

static inline struct domain_set *find_set(struct domain_set_net *inst,
					  const char *name)
{
	domain_set_id_t id;

	return find_set_and_id(inst, name, &id);
}

static int find_free_id(struct domain_set_net *inst, const char *name,
			domain_set_id_t *index, struct domain_set **set)
{
	struct domain_set *s;
	domain_set_id_t i;

	*index = DSET_INVALID_ID;
	for (i = 0; i < inst->domain_set_max; i++) {
		s = domain_set(inst, i);
		if (!s) {
			if (*index == DSET_INVALID_ID)
				*index = i;
		} else if (STRNCMP(name, s->name)) {
			/* Name clash */
			*set = s;
			return -EEXIST;
		}
	}
	if (*index == DSET_INVALID_ID)
		/* No free slot remained */
		return -DSET_ERR_MAX_SETS;
	return 0;
}

static int DSET_CBFN(domain_set_none, struct net *net, struct sock *ctnl,
		     struct sk_buff *skb, const struct nlmsghdr *nlh,
		     const struct nlattr *const attr[],
		     struct netlink_ext_ack *extack)
{
	return -EOPNOTSUPP;
}

static int DSET_CBFN(domain_set_create, struct net *n, struct sock *ctnl,
		     struct sk_buff *skb, const struct nlmsghdr *nlh,
		     const struct nlattr *const attr[],
		     struct netlink_ext_ack *extack)
{
	struct net *net = DSET_SOCK_NET(n, ctnl);
	struct domain_set_net *inst = domain_set_pernet(net);
	struct domain_set *set, *clash = NULL;
	domain_set_id_t index = DSET_INVALID_ID;
	struct nlattr *tb[DSET_ATTR_CREATE_MAX + 1] = {};
	const char *name, *typename;
	u8 family, revision;
	u32 flags = flag_exist(nlh);
	int ret = 0;

	if (unlikely(protocol_min_failed(attr) || !attr[DSET_ATTR_SETNAME] ||
		     !attr[DSET_ATTR_TYPENAME] || !attr[DSET_ATTR_REVISION] ||
		     !attr[DSET_ATTR_FAMILY] ||
		     (attr[DSET_ATTR_DATA] &&
		      !flag_nested(attr[DSET_ATTR_DATA]))))
		return -DSET_ERR_PROTOCOL;

	name = nla_data(attr[DSET_ATTR_SETNAME]);
	typename = nla_data(attr[DSET_ATTR_TYPENAME]);
	family = nla_get_u8(attr[DSET_ATTR_FAMILY]);
	revision = nla_get_u8(attr[DSET_ATTR_REVISION]);
	pr_debug("setname: %s, typename: %s, family: %s, revision: %u\n", name,
		 typename, family_name(family), revision);

	/* First, and without any locks, allocate and initialize
	 * a normal base set structure.
	 */
	set = kzalloc(sizeof(*set), GFP_KERNEL);
	if (!set)
		return -ENOMEM;
	spin_lock_init(&set->lock);
	strlcpy(set->name, name, DSET_MAXNAMELEN);
	set->family = family;
	set->revision = revision;

	/* Next, check that we know the type, and take
	 * a reference on the type, to make sure it stays available
	 * while constructing our new set.
	 *
	 * After referencing the type, we try to create the type
	 * specific part of the set without holding any locks.
	 */
	ret = find_set_type_get(typename, family, revision, &set->type);
	if (ret)
		goto out;

	/* Without holding any locks, create private part. */
	if (attr[DSET_ATTR_DATA] &&
	    NLA_PARSE_NESTED(tb, DSET_ATTR_CREATE_MAX, attr[DSET_ATTR_DATA],
			     set->type->create_policy, NULL)) {
		ret = -DSET_ERR_PROTOCOL;
		goto put_out;
	}

	ret = set->type->create(net, set, tb, flags);
	if (ret != 0)
		goto put_out;

	/* BTW, ret==0 here. */

	/* Here, we have a valid, constructed set and we are protected
	 * by the nfnl mutex. Find the first free index in domain_set_list
	 * and check clashing.
	 */
	ret = find_free_id(inst, set->name, &index, &clash);
	if (ret == -EEXIST) {
		/* If this is the same set and requested, ignore error */
		if ((flags & DSET_FLAG_EXIST) &&
		    STRNCMP(set->type->name, clash->type->name) &&
		    set->type->family == clash->type->family &&
		    set->type->revision_min == clash->type->revision_min &&
		    set->type->revision_max == clash->type->revision_max &&
		    set->variant->same_set(set, clash))
			ret = 0;
		goto cleanup;
	} else if (ret == -DSET_ERR_MAX_SETS) {
		struct domain_set **list, **tmp;
		domain_set_id_t i = inst->domain_set_max + DOMAIN_SET_INC;

		if (i < inst->domain_set_max || i == DSET_INVALID_ID)
			/* Wraparound */
			goto cleanup;

		list = kvcalloc(i, sizeof(struct domain_set *), GFP_KERNEL);
		if (!list)
			goto cleanup;
		/* nfnl mutex is held, both lists are valid */
		tmp = domain_set_dereference(inst->domain_set_list);
		memcpy(list, tmp,
		       sizeof(struct domain_set *) * inst->domain_set_max);
		rcu_assign_pointer(inst->domain_set_list, list);
		/* Make sure all current packets have passed through */
		synchronize_net();
		/* Use new list */
		index = inst->domain_set_max;
		inst->domain_set_max = i;
		kvfree(tmp);
		ret = 0;
	} else if (ret) {
		goto cleanup;
	}

	/* Finally! Add our shiny new set to the list, and be done. */
	pr_debug("create: '%s' created with index %u!\n", set->name, index);
	domain_set(inst, index) = set;

	return ret;

cleanup:
	set->variant->destroy(set);
put_out:
	module_put(set->type->me);
out:
	kfree(set);
	return ret;
}

/* Destroy sets */

static const struct nla_policy
	domain_set_setname_policy[DSET_ATTR_CMD_MAX + 1] = {
		[DSET_ATTR_PROTOCOL] = { .type = NLA_U8 },
		[DSET_ATTR_SETNAME] = { .type = NLA_NUL_STRING,
					.len = DSET_MAXNAMELEN - 1 },
	};

static void domain_set_destroy_set(struct domain_set *set)
{
	pr_debug("set: %s\n", set->name);

	/* Must call it without holding any lock */
	set->variant->destroy(set);
	module_put(set->type->me);
	kfree(set);
}

static int DSET_CBFN(domain_set_destroy, struct net *net, struct sock *ctnl,
		     struct sk_buff *skb, const struct nlmsghdr *nlh,
		     const struct nlattr *const attr[],
		     struct netlink_ext_ack *extack)
{
	struct domain_set_net *inst =
		domain_set_pernet(DSET_SOCK_NET(net, ctnl));
	struct domain_set *s;
	domain_set_id_t i;
	int ret = 0;

	if (unlikely(protocol_min_failed(attr)))
		return -DSET_ERR_PROTOCOL;

	/* Must wait for flush to be really finished in list:set */
	rcu_barrier();

	/* Commands are serialized and references are
	 * protected by the domain_set_ref_lock.
	 * External systems (i.e. xt_set) must call
	 * domain_set_put|get_nfnl_* functions, that way we
	 * can safely check references here.
	 *
	 * list:set timer can only decrement the reference
	 * counter, so if it's already zero, we can proceed
	 * without holding the lock.
	 */
	read_lock_bh(&domain_set_ref_lock);
	if (!attr[DSET_ATTR_SETNAME]) {
		for (i = 0; i < inst->domain_set_max; i++) {
			s = domain_set(inst, i);
			if (s && (s->ref || s->ref_netlink)) {
				ret = -DSET_ERR_BUSY;
				goto out;
			}
		}
		inst->is_destroyed = true;
		read_unlock_bh(&domain_set_ref_lock);
		for (i = 0; i < inst->domain_set_max; i++) {
			s = domain_set(inst, i);
			if (s) {
				domain_set(inst, i) = NULL;
				domain_set_destroy_set(s);
			}
		}
		/* Modified by domain_set_destroy() only, which is serialized */
		inst->is_destroyed = false;
	} else {
		s = find_set_and_id(inst, nla_data(attr[DSET_ATTR_SETNAME]),
				    &i);
		if (!s) {
			ret = -ENOENT;
			goto out;
		} else if (s->ref || s->ref_netlink) {
			ret = -DSET_ERR_BUSY;
			goto out;
		}
		domain_set(inst, i) = NULL;
		read_unlock_bh(&domain_set_ref_lock);

		domain_set_destroy_set(s);
	}
	return 0;
out:
	read_unlock_bh(&domain_set_ref_lock);
	return ret;
}

/* Flush sets */

static void domain_set_flush_set(struct domain_set *set)
{
	pr_debug("set: %s\n", set->name);

	spin_lock_bh(&set->lock);
	set->variant->flush(set);
	spin_unlock_bh(&set->lock);
}

static int DSET_CBFN(domain_set_flush, struct net *net, struct sock *ctnl,
		     struct sk_buff *skb, const struct nlmsghdr *nlh,
		     const struct nlattr *const attr[],
		     struct netlink_ext_ack *extack)
{
	struct domain_set_net *inst =
		domain_set_pernet(DSET_SOCK_NET(net, ctnl));
	struct domain_set *s;
	domain_set_id_t i;

	if (unlikely(protocol_min_failed(attr)))
		return -DSET_ERR_PROTOCOL;

	if (!attr[DSET_ATTR_SETNAME]) {
		for (i = 0; i < inst->domain_set_max; i++) {
			s = domain_set(inst, i);
			if (s)
				domain_set_flush_set(s);
		}
	} else {
		s = find_set(inst, nla_data(attr[DSET_ATTR_SETNAME]));
		if (!s)
			return -ENOENT;

		domain_set_flush_set(s);
	}

	return 0;
}

/* Rename a set */

static const struct nla_policy
	domain_set_setname2_policy[DSET_ATTR_CMD_MAX + 1] = {
		[DSET_ATTR_PROTOCOL] = { .type = NLA_U8 },
		[DSET_ATTR_SETNAME] = { .type = NLA_NUL_STRING,
					.len = DSET_MAXNAMELEN - 1 },
		[DSET_ATTR_SETNAME2] = { .type = NLA_NUL_STRING,
					 .len = DSET_MAXNAMELEN - 1 },
	};

static int DSET_CBFN(domain_set_rename, struct net *net, struct sock *ctnl,
		     struct sk_buff *skb, const struct nlmsghdr *nlh,
		     const struct nlattr *const attr[],
		     struct netlink_ext_ack *extack)
{
	struct domain_set_net *inst =
		domain_set_pernet(DSET_SOCK_NET(net, ctnl));
	struct domain_set *set, *s;
	const char *name2;
	domain_set_id_t i;
	int ret = 0;

	if (unlikely(protocol_min_failed(attr) || !attr[DSET_ATTR_SETNAME] ||
		     !attr[DSET_ATTR_SETNAME2]))
		return -DSET_ERR_PROTOCOL;

	set = find_set(inst, nla_data(attr[DSET_ATTR_SETNAME]));
	if (!set)
		return -ENOENT;

	write_lock_bh(&domain_set_ref_lock);
	if (set->ref != 0 || set->ref_netlink != 0) {
		ret = -DSET_ERR_REFERENCED;
		goto out;
	}

	name2 = nla_data(attr[DSET_ATTR_SETNAME2]);
	for (i = 0; i < inst->domain_set_max; i++) {
		s = domain_set(inst, i);
		if (s && STRNCMP(s->name, name2)) {
			ret = -DSET_ERR_EXIST_SETNAME2;
			goto out;
		}
	}
	strncpy(set->name, name2, DSET_MAXNAMELEN);

out:
	write_unlock_bh(&domain_set_ref_lock);
	return ret;
}

/* Swap two sets so that name/index points to the other.
 * References and set names are also swapped.
 *
 * The commands are serialized by the nfnl mutex and references are
 * protected by the domain_set_ref_lock. The kernel interfaces
 * do not hold the mutex but the pointer settings are atomic
 * so the domain_set_list always contains valid pointers to the sets.
 */

static int DSET_CBFN(domain_set_swap, struct net *net, struct sock *ctnl,
		     struct sk_buff *skb, const struct nlmsghdr *nlh,
		     const struct nlattr *const attr[],
		     struct netlink_ext_ack *extack)
{
	struct domain_set_net *inst =
		domain_set_pernet(DSET_SOCK_NET(net, ctnl));
	struct domain_set *from, *to;
	domain_set_id_t from_id, to_id;
	char from_name[DSET_MAXNAMELEN];

	if (unlikely(protocol_min_failed(attr) || !attr[DSET_ATTR_SETNAME] ||
		     !attr[DSET_ATTR_SETNAME2]))
		return -DSET_ERR_PROTOCOL;

	from = find_set_and_id(inst, nla_data(attr[DSET_ATTR_SETNAME]),
			       &from_id);
	if (!from)
		return -ENOENT;

	to = find_set_and_id(inst, nla_data(attr[DSET_ATTR_SETNAME2]), &to_id);
	if (!to)
		return -DSET_ERR_EXIST_SETNAME2;

	/* Features must not change.
	 * Not an artifical restriction anymore, as we must prevent
	 * possible loops created by swapping in setlist type of sets.
	 */
	if (!(from->type->features == to->type->features &&
	      from->family == to->family))
		return -DSET_ERR_TYPE_MISMATCH;

	write_lock_bh(&domain_set_ref_lock);

	if (from->ref_netlink || to->ref_netlink) {
		write_unlock_bh(&domain_set_ref_lock);
		return -EBUSY;
	}

	strncpy(from_name, from->name, DSET_MAXNAMELEN);
	strncpy(from->name, to->name, DSET_MAXNAMELEN);
	strncpy(to->name, from_name, DSET_MAXNAMELEN);

	swap(from->ref, to->ref);
	domain_set(inst, from_id) = to;
	domain_set(inst, to_id) = from;
	write_unlock_bh(&domain_set_ref_lock);

	return 0;
}

/* List/save set data */

#define DUMP_INIT 0
#define DUMP_ALL 1
#define DUMP_ONE 2
#define DUMP_LAST 3

#define DUMP_TYPE(arg) (((u32)(arg)) & 0x0000FFFF)
#define DUMP_FLAGS(arg) (((u32)(arg)) >> 16)

int domain_set_put_flags(struct sk_buff *skb, struct domain_set *set)
{
	u32 cadt_flags = 0;

	if (SET_WITH_TIMEOUT(set))
		if (unlikely(nla_put_net32(skb, DSET_ATTR_TIMEOUT,
					   htonl(set->timeout))))
			return -EMSGSIZE;
	if (SET_WITH_COUNTER(set))
		cadt_flags |= DSET_FLAG_WITH_COUNTERS;
	if (SET_WITH_COMMENT(set))
		cadt_flags |= DSET_FLAG_WITH_COMMENT;
	if (SET_WITH_SKBINFO(set))
		cadt_flags |= DSET_FLAG_WITH_SKBINFO;
	if (SET_WITH_FORCEADD(set))
		cadt_flags |= DSET_FLAG_WITH_FORCEADD;

	if (!cadt_flags)
		return 0;
	return nla_put_net32(skb, DSET_ATTR_CADT_FLAGS, htonl(cadt_flags));
}
EXPORT_SYMBOL_GPL(domain_set_put_flags);

static int domain_set_dump_done(struct netlink_callback *cb)
{
	if (cb->args[DSET_CB_ARG0]) {
		struct domain_set_net *inst =
			(struct domain_set_net *)cb->args[DSET_CB_NET];
		domain_set_id_t index =
			(domain_set_id_t)cb->args[DSET_CB_INDEX];
		struct domain_set *set = domain_set_ref_netlink(inst, index);

		if (set->variant->uref)
			set->variant->uref(set, cb, false);
		pr_debug("release set %s\n", set->name);
		__domain_set_put_netlink(set);
	}
	return 0;
}

static inline void dump_attrs(struct nlmsghdr *nlh)
{
	const struct nlattr *attr;
	int rem;

	pr_debug("dump nlmsg\n");
	nlmsg_for_each_attr (attr, nlh, sizeof(struct nfgenmsg), rem) {
		pr_debug("type: %u, len %u\n", nla_type(attr), attr->nla_len);
	}
}

static int dump_init(struct netlink_callback *cb, struct domain_set_net *inst)
{
	struct nlmsghdr *nlh = nlmsg_hdr(cb->skb);
	int min_len = nlmsg_total_size(sizeof(struct nfgenmsg));
	struct nlattr *cda[DSET_ATTR_CMD_MAX + 1];
	struct nlattr *attr = (void *)nlh + min_len;
	u32 dump_type;
	domain_set_id_t index;
	int ret;

	ret = NLA_PARSE(cda, DSET_ATTR_CMD_MAX, attr, nlh->nlmsg_len - min_len,
			domain_set_setname_policy, NULL);
	if (ret)
		return ret;

	cb->args[DSET_CB_PROTO] = nla_get_u8(cda[DSET_ATTR_PROTOCOL]);
	if (cda[DSET_ATTR_SETNAME]) {
		struct domain_set *set;

		set = find_set_and_id(inst, nla_data(cda[DSET_ATTR_SETNAME]),
				      &index);
		if (!set)
			return -ENOENT;

		dump_type = DUMP_ONE;
		cb->args[DSET_CB_INDEX] = index;
	} else {
		dump_type = DUMP_ALL;
	}

	if (cda[DSET_ATTR_FLAGS]) {
		u32 f = domain_set_get_h32(cda[DSET_ATTR_FLAGS]);

		dump_type |= (f << 16);
	}
	cb->args[DSET_CB_NET] = (unsigned long)inst;
	cb->args[DSET_CB_DUMP] = dump_type;

	return 0;
}

static int domain_set_dump_start(struct sk_buff *skb,
				 struct netlink_callback *cb)
{
	domain_set_id_t index = DSET_INVALID_ID, max;
	struct domain_set *set = NULL;
	struct nlmsghdr *nlh = NULL;
	unsigned int flags = NETLINK_PORTID(cb->skb) ? NLM_F_MULTI : 0;
	struct domain_set_net *inst = domain_set_pernet(sock_net(skb->sk));
	u32 dump_type, dump_flags;
	bool is_destroyed;
	int ret = 0;

	if (!cb->args[DSET_CB_DUMP]) {
		ret = dump_init(cb, inst);
		if (ret < 0) {
			nlh = nlmsg_hdr(cb->skb);
			/* We have to create and send the error message
			 * manually :-(
			 */
			if (nlh->nlmsg_flags & NLM_F_ACK)
				NETLINK_ACK(cb->skb, nlh, ret, NULL);
			return ret;
		}
	}

	if (cb->args[DSET_CB_INDEX] >= inst->domain_set_max)
		goto out;

	dump_type = DUMP_TYPE(cb->args[DSET_CB_DUMP]);
	dump_flags = DUMP_FLAGS(cb->args[DSET_CB_DUMP]);
	max = dump_type == DUMP_ONE ? cb->args[DSET_CB_INDEX] + 1 :
				      inst->domain_set_max;
dump_last:
	pr_debug("dump type, flag: %u %u index: %ld\n", dump_type, dump_flags,
		 cb->args[DSET_CB_INDEX]);
	for (; cb->args[DSET_CB_INDEX] < max; cb->args[DSET_CB_INDEX]++) {
		index = (domain_set_id_t)cb->args[DSET_CB_INDEX];
		write_lock_bh(&domain_set_ref_lock);
		set = domain_set(inst, index);
		is_destroyed = inst->is_destroyed;
		if (!set || is_destroyed) {
			write_unlock_bh(&domain_set_ref_lock);
			if (dump_type == DUMP_ONE) {
				ret = -ENOENT;
				goto out;
			}
			if (is_destroyed) {
				/* All sets are just being destroyed */
				ret = 0;
				goto out;
			}
			continue;
		}
		/* When dumping all sets, we must dump "sorted"
		 * so that lists (unions of sets) are dumped last.
		 */
		if (dump_type != DUMP_ONE &&
		    ((dump_type == DUMP_ALL) ==
		     !!(set->type->features & DSET_DUMP_LAST))) {
			write_unlock_bh(&domain_set_ref_lock);
			continue;
		}
		pr_debug("List set: %s\n", set->name);
		if (!cb->args[DSET_CB_ARG0]) {
			/* Start listing: make sure set won't be destroyed */
			pr_debug("reference set\n");
			set->ref_netlink++;
		}
		write_unlock_bh(&domain_set_ref_lock);
		nlh = start_msg(skb, NETLINK_PORTID(cb->skb),
				cb->nlh->nlmsg_seq, flags, DSET_CMD_LIST);
		if (!nlh) {
			ret = -EMSGSIZE;
			goto release_refcount;
		}
		if (nla_put_u8(skb, DSET_ATTR_PROTOCOL,
			       cb->args[DSET_CB_PROTO]) ||
		    nla_put_string(skb, DSET_ATTR_SETNAME, set->name))
			goto nla_put_failure;
		if (dump_flags & DSET_FLAG_LIST_SETNAME)
			goto next_set;
		switch (cb->args[DSET_CB_ARG0]) {
		case 0:
			/* Core header data */
			if (nla_put_string(skb, DSET_ATTR_TYPENAME,
					   set->type->name) ||
			    nla_put_u8(skb, DSET_ATTR_FAMILY, set->family) ||
			    nla_put_u8(skb, DSET_ATTR_REVISION, set->revision))
				goto nla_put_failure;
			if (cb->args[DSET_CB_PROTO] > DSET_PROTOCOL_MIN &&
			    nla_put_net16(skb, DSET_ATTR_INDEX, htons(index)))
				goto nla_put_failure;
			ret = set->variant->head(set, skb);
			if (ret < 0)
				goto release_refcount;
			if (dump_flags & DSET_FLAG_LIST_HEADER)
				goto next_set;
			if (set->variant->uref)
				set->variant->uref(set, cb, true);
			/* fall through */
		default:
			ret = set->variant->list(set, skb, cb);
			if (!cb->args[DSET_CB_ARG0])
				/* Set is done, proceed with next one */
				goto next_set;
			goto release_refcount;
		}
	}
	/* If we dump all sets, continue with dumping last ones */
	if (dump_type == DUMP_ALL) {
		dump_type = DUMP_LAST;
		cb->args[DSET_CB_DUMP] = dump_type | (dump_flags << 16);
		cb->args[DSET_CB_INDEX] = 0;
		if (set && set->variant->uref)
			set->variant->uref(set, cb, false);
		goto dump_last;
	}
	goto out;

nla_put_failure:
	ret = -EFAULT;
next_set:
	if (dump_type == DUMP_ONE)
		cb->args[DSET_CB_INDEX] = DSET_INVALID_ID;
	else
		cb->args[DSET_CB_INDEX]++;
release_refcount:
	/* If there was an error or set is done, release set */
	if (ret || !cb->args[DSET_CB_ARG0]) {
		set = domain_set_ref_netlink(inst, index);
		if (set->variant->uref)
			set->variant->uref(set, cb, false);
		pr_debug("release set %s\n", set->name);
		__domain_set_put_netlink(set);
		cb->args[DSET_CB_ARG0] = 0;
	}
out:
	if (nlh) {
		nlmsg_end(skb, nlh);
		pr_debug("nlmsg_len: %u\n", nlh->nlmsg_len);
		dump_attrs(nlh);
	}

	return ret < 0 ? ret : skb->len;
}

static int DSET_CBFN(domain_set_dump, struct net *net, struct sock *ctnl,
		     struct sk_buff *skb, const struct nlmsghdr *nlh,
		     const struct nlattr *const attr[],
		     struct netlink_ext_ack *extack)
{
	if (unlikely(protocol_min_failed(attr)))
		return -DSET_ERR_PROTOCOL;

#if HAVE_NETLINK_DUMP_START_ARGS == 5
	return netlink_dump_start(ctnl, skb, nlh, domain_set_dump_start,
				  domain_set_dump_done);
#elif HAVE_NETLINK_DUMP_START_ARGS == 6
	return netlink_dump_start(ctnl, skb, nlh, domain_set_dump_start,
				  domain_set_dump_done, 0);
#else
	{
		struct netlink_dump_control c = {
			.dump = domain_set_dump_start,
			.done = domain_set_dump_done,
		};
		return netlink_dump_start(ctnl, skb, nlh, &c);
	}
#endif
}

/* Add, del and test */

static const struct nla_policy domain_set_adt_policy[DSET_ATTR_CMD_MAX + 1] = {
	[DSET_ATTR_PROTOCOL] = { .type = NLA_U8 },
	[DSET_ATTR_SETNAME] = { .type = NLA_NUL_STRING,
				.len = DSET_MAXNAMELEN - 1 },
	[DSET_ATTR_LINENO] = { .type = NLA_U32 },
	[DSET_ATTR_DATA] = { .type = NLA_NESTED },
	[DSET_ATTR_ADT] = { .type = NLA_NESTED },
};

static int call_ad(struct sock *ctnl, struct sk_buff *skb,
		   struct domain_set *set, struct nlattr *tb[],
		   enum dset_adt adt, u32 flags, bool use_lineno)
{
	int ret;
	u32 lineno = 0;
	bool eexist = flags & DSET_FLAG_EXIST, retried = false;

	do {
		spin_lock_bh(&set->lock);
		ret = set->variant->uadt(set, tb, adt, &lineno, flags, retried);
		spin_unlock_bh(&set->lock);
		retried = true;
	} while (ret == -EAGAIN && set->variant->resize &&
		 (ret = set->variant->resize(set, retried)) == 0);

	if (!ret || (ret == -DSET_ERR_EXIST && eexist))
		return 0;
	if (lineno && use_lineno) {
		/* Error in restore/batch mode: send back lineno */
		struct nlmsghdr *rep, *nlh = nlmsg_hdr(skb);
		struct sk_buff *skb2;
		struct nlmsgerr *errmsg;
		size_t payload =
			min(SIZE_MAX, sizeof(*errmsg) + nlmsg_len(nlh));
		int min_len = nlmsg_total_size(sizeof(struct nfgenmsg));
		struct nlattr *cda[DSET_ATTR_CMD_MAX + 1];
		struct nlattr *cmdattr;
		u32 *errline;

		skb2 = nlmsg_new(payload, GFP_KERNEL);
		if (!skb2)
			return -ENOMEM;
		rep = __nlmsg_put(skb2, NETLINK_PORTID(skb), nlh->nlmsg_seq,
				  NLMSG_ERROR, payload, 0);
		errmsg = nlmsg_data(rep);
		errmsg->error = ret;
		memcpy(&errmsg->msg, nlh, nlh->nlmsg_len);
		cmdattr = (void *)&errmsg->msg + min_len;

		ret = NLA_PARSE(cda, DSET_ATTR_CMD_MAX, cmdattr,
				nlh->nlmsg_len - min_len, domain_set_adt_policy,
				NULL);

		if (ret) {
			nlmsg_free(skb2);
			return ret;
		}
		errline = nla_data(cda[DSET_ATTR_LINENO]);

		*errline = lineno;

		netlink_unicast(ctnl, skb2, NETLINK_PORTID(skb), MSG_DONTWAIT);
		/* Signal netlink not to send its ACK/errmsg.  */
		return -EINTR;
	}

	return ret;
}

static int DSET_CBFN_AD(domain_set_ad, struct net *net, struct sock *ctnl,
			struct sk_buff *skb, enum dset_adt adt,
			const struct nlmsghdr *nlh,
			const struct nlattr *const attr[],
			struct netlink_ext_ack *extack)
{
	struct domain_set_net *inst =
		domain_set_pernet(DSET_SOCK_NET(net, ctnl));
	struct domain_set *set;
	struct nlattr *tb[DSET_ATTR_ADT_MAX + 1] = {};
	const struct nlattr *nla;
	u32 flags = flag_exist(nlh);
	bool use_lineno;
	int ret = 0;

	if (unlikely(protocol_min_failed(attr) || !attr[DSET_ATTR_SETNAME] ||
		     !((attr[DSET_ATTR_DATA] != NULL) ^
		       (attr[DSET_ATTR_ADT] != NULL)) ||
		     (attr[DSET_ATTR_DATA] &&
		      !flag_nested(attr[DSET_ATTR_DATA])) ||
		     (attr[DSET_ATTR_ADT] &&
		      (!flag_nested(attr[DSET_ATTR_ADT]) ||
		       !attr[DSET_ATTR_LINENO]))))
		return -DSET_ERR_PROTOCOL;

	set = find_set(inst, nla_data(attr[DSET_ATTR_SETNAME]));
	if (!set)
		return -ENOENT;

	use_lineno = !!attr[DSET_ATTR_LINENO];
	if (attr[DSET_ATTR_DATA]) {
		if (NLA_PARSE_NESTED(tb, DSET_ATTR_ADT_MAX,
				     attr[DSET_ATTR_DATA],
				     set->type->adt_policy, NULL))
			return -DSET_ERR_PROTOCOL;
		ret = call_ad(ctnl, skb, set, tb, adt, flags, use_lineno);
	} else {
		int nla_rem;

		nla_for_each_nested (nla, attr[DSET_ATTR_ADT], nla_rem) {
			if (nla_type(nla) != DSET_ATTR_DATA ||
			    !flag_nested(nla) ||
			    NLA_PARSE_NESTED(tb, DSET_ATTR_ADT_MAX, nla,
					     set->type->adt_policy, NULL))
				return -DSET_ERR_PROTOCOL;
			ret = call_ad(ctnl, skb, set, tb, adt, flags,
				      use_lineno);
			if (ret < 0)
				return ret;
		}
	}
	return ret;
}

static int DSET_CBFN(domain_set_uadd, struct net *net, struct sock *ctnl,
		     struct sk_buff *skb, const struct nlmsghdr *nlh,
		     const struct nlattr *const attr[],
		     struct netlink_ext_ack *extack)
{
	return DSET_CBFN_AD(domain_set_ad, net, ctnl, skb, DSET_ADD, nlh, attr,
			    extack);
}

static int DSET_CBFN(domain_set_udel, struct net *net, struct sock *ctnl,
		     struct sk_buff *skb, const struct nlmsghdr *nlh,
		     const struct nlattr *const attr[],
		     struct netlink_ext_ack *extack)
{
	return DSET_CBFN_AD(domain_set_ad, net, ctnl, skb, DSET_DEL, nlh, attr,
			    extack);
}

static int DSET_CBFN(domain_set_utest, struct net *net, struct sock *ctnl,
		     struct sk_buff *skb, const struct nlmsghdr *nlh,
		     const struct nlattr *const attr[],
		     struct netlink_ext_ack *extack)
{
	struct domain_set_net *inst =
		domain_set_pernet(DSET_SOCK_NET(net, ctnl));
	struct domain_set *set;
	struct nlattr *tb[DSET_ATTR_ADT_MAX + 1] = {};
	int ret = 0;

	if (unlikely(protocol_min_failed(attr) || !attr[DSET_ATTR_SETNAME] ||
		     !attr[DSET_ATTR_DATA] ||
		     !flag_nested(attr[DSET_ATTR_DATA])))
		return -DSET_ERR_PROTOCOL;

	set = find_set(inst, nla_data(attr[DSET_ATTR_SETNAME]));
	if (!set)
		return -ENOENT;

	if (NLA_PARSE_NESTED(tb, DSET_ATTR_ADT_MAX, attr[DSET_ATTR_DATA],
			     set->type->adt_policy, NULL))
		return -DSET_ERR_PROTOCOL;

	rcu_read_lock_bh();
	ret = set->variant->uadt(set, tb, DSET_TEST, NULL, 0, 0);
	rcu_read_unlock_bh();
	/* Userspace can't trigger element to be re-added */
	if (ret == -EAGAIN)
		ret = 1;

	return ret > 0 ? 0 : -DSET_ERR_EXIST;
}

/* Get headed data of a set */

static int DSET_CBFN(domain_set_header, struct net *net, struct sock *ctnl,
		     struct sk_buff *skb, const struct nlmsghdr *nlh,
		     const struct nlattr *const attr[],
		     struct netlink_ext_ack *extack)
{
	struct domain_set_net *inst =
		domain_set_pernet(DSET_SOCK_NET(net, ctnl));
	const struct domain_set *set;
	struct sk_buff *skb2;
	struct nlmsghdr *nlh2;
	int ret = 0;

	if (unlikely(protocol_min_failed(attr) || !attr[DSET_ATTR_SETNAME]))
		return -DSET_ERR_PROTOCOL;

	set = find_set(inst, nla_data(attr[DSET_ATTR_SETNAME]));
	if (!set)
		return -ENOENT;

	skb2 = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb2)
		return -ENOMEM;

	nlh2 = start_msg(skb2, NETLINK_PORTID(skb), nlh->nlmsg_seq, 0,
			 DSET_CMD_HEADER);
	if (!nlh2)
		goto nlmsg_failure;
	if (nla_put_u8(skb2, DSET_ATTR_PROTOCOL, protocol(attr)) ||
	    nla_put_string(skb2, DSET_ATTR_SETNAME, set->name) ||
	    nla_put_string(skb2, DSET_ATTR_TYPENAME, set->type->name) ||
	    nla_put_u8(skb2, DSET_ATTR_FAMILY, set->family) ||
	    nla_put_u8(skb2, DSET_ATTR_REVISION, set->revision))
		goto nla_put_failure;
	nlmsg_end(skb2, nlh2);

	ret = netlink_unicast(ctnl, skb2, NETLINK_PORTID(skb), MSG_DONTWAIT);
	if (ret < 0)
		return ret;

	return 0;

nla_put_failure:
	nlmsg_cancel(skb2, nlh2);
nlmsg_failure:
	kfree_skb(skb2);
	return -EMSGSIZE;
}

/* Get type data */

static const struct nla_policy domain_set_type_policy[DSET_ATTR_CMD_MAX + 1] = {
	[DSET_ATTR_PROTOCOL] = { .type = NLA_U8 },
	[DSET_ATTR_TYPENAME] = { .type = NLA_NUL_STRING,
				 .len = DSET_MAXNAMELEN - 1 },
	[DSET_ATTR_FAMILY] = { .type = NLA_U8 },
};

static int DSET_CBFN(domain_set_type, struct net *net, struct sock *ctnl,
		     struct sk_buff *skb, const struct nlmsghdr *nlh,
		     const struct nlattr *const attr[],
		     struct netlink_ext_ack *extack)
{
	struct sk_buff *skb2;
	struct nlmsghdr *nlh2;
	u8 family, min, max;
	const char *typename;
	int ret = 0;

	if (unlikely(protocol_min_failed(attr) || !attr[DSET_ATTR_TYPENAME] ||
		     !attr[DSET_ATTR_FAMILY]))
		return -DSET_ERR_PROTOCOL;

	family = nla_get_u8(attr[DSET_ATTR_FAMILY]);
	typename = nla_data(attr[DSET_ATTR_TYPENAME]);
	ret = find_set_type_minmax(typename, family, &min, &max);
	if (ret)
		return ret;

	skb2 = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb2)
		return -ENOMEM;

	nlh2 = start_msg(skb2, NETLINK_PORTID(skb), nlh->nlmsg_seq, 0,
			 DSET_CMD_TYPE);
	if (!nlh2)
		goto nlmsg_failure;
	if (nla_put_u8(skb2, DSET_ATTR_PROTOCOL, protocol(attr)) ||
	    nla_put_string(skb2, DSET_ATTR_TYPENAME, typename) ||
	    nla_put_u8(skb2, DSET_ATTR_FAMILY, family) ||
	    nla_put_u8(skb2, DSET_ATTR_REVISION, max) ||
	    nla_put_u8(skb2, DSET_ATTR_REVISION_MIN, min))
		goto nla_put_failure;
	nlmsg_end(skb2, nlh2);

	pr_debug("Send TYPE, nlmsg_len: %u\n", nlh2->nlmsg_len);
	ret = netlink_unicast(ctnl, skb2, NETLINK_PORTID(skb), MSG_DONTWAIT);
	if (ret < 0)
		return ret;

	return 0;

nla_put_failure:
	nlmsg_cancel(skb2, nlh2);
nlmsg_failure:
	kfree_skb(skb2);
	return -EMSGSIZE;
}

/* Get protocol version */

static const struct nla_policy
	domain_set_protocol_policy[DSET_ATTR_CMD_MAX + 1] = {
		[DSET_ATTR_PROTOCOL] = { .type = NLA_U8 },
	};

static int DSET_CBFN(domain_set_protocol, struct net *net, struct sock *ctnl,
		     struct sk_buff *skb, const struct nlmsghdr *nlh,
		     const struct nlattr *const attr[],
		     struct netlink_ext_ack *extack)
{
	struct sk_buff *skb2;
	struct nlmsghdr *nlh2;
	int ret = 0;

	if (unlikely(!attr[DSET_ATTR_PROTOCOL]))
		return -DSET_ERR_PROTOCOL;

	skb2 = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb2)
		return -ENOMEM;

	nlh2 = start_msg(skb2, NETLINK_PORTID(skb), nlh->nlmsg_seq, 0,
			 DSET_CMD_PROTOCOL);
	if (!nlh2)
		goto nlmsg_failure;
	if (nla_put_u8(skb2, DSET_ATTR_PROTOCOL, DSET_PROTOCOL))
		goto nla_put_failure;
	if (nla_put_u8(skb2, DSET_ATTR_PROTOCOL_MIN, DSET_PROTOCOL_MIN))
		goto nla_put_failure;
	nlmsg_end(skb2, nlh2);

	ret = netlink_unicast(ctnl, skb2, NETLINK_PORTID(skb), MSG_DONTWAIT);
	if (ret < 0)
		return ret;

	return 0;

nla_put_failure:
	nlmsg_cancel(skb2, nlh2);
nlmsg_failure:
	kfree_skb(skb2);
	return -EMSGSIZE;
}

/* Get set by name or index, from userspace */

static int DSET_CBFN(domain_set_byname, struct net *net, struct sock *ctnl,
		     struct sk_buff *skb, const struct nlmsghdr *nlh,
		     const struct nlattr *const attr[],
		     struct netlink_ext_ack *extack)
{
	struct domain_set_net *inst =
		domain_set_pernet(DSET_SOCK_NET(net, ctnl));
	struct sk_buff *skb2;
	struct nlmsghdr *nlh2;
	domain_set_id_t id = DSET_INVALID_ID;
	const struct domain_set *set;
	int ret = 0;

	if (unlikely(protocol_failed(attr) || !attr[DSET_ATTR_SETNAME]))
		return -DSET_ERR_PROTOCOL;

	set = find_set_and_id(inst, nla_data(attr[DSET_ATTR_SETNAME]), &id);
	if (id == DSET_INVALID_ID)
		return -ENOENT;

	skb2 = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb2)
		return -ENOMEM;

	nlh2 = start_msg(skb2, NETLINK_PORTID(skb), nlh->nlmsg_seq, 0,
			 DSET_CMD_GET_BYNAME);
	if (!nlh2)
		goto nlmsg_failure;
	if (nla_put_u8(skb2, DSET_ATTR_PROTOCOL, protocol(attr)) ||
	    nla_put_u8(skb2, DSET_ATTR_FAMILY, set->family) ||
	    nla_put_net16(skb2, DSET_ATTR_INDEX, htons(id)))
		goto nla_put_failure;
	nlmsg_end(skb2, nlh2);

	ret = netlink_unicast(ctnl, skb2, NETLINK_PORTID(skb), MSG_DONTWAIT);
	if (ret < 0)
		return ret;

	return 0;

nla_put_failure:
	nlmsg_cancel(skb2, nlh2);
nlmsg_failure:
	kfree_skb(skb2);
	return -EMSGSIZE;
}

static const struct nla_policy domain_set_index_policy[DSET_ATTR_CMD_MAX + 1] = {
	[DSET_ATTR_PROTOCOL] = { .type = NLA_U8 },
	[DSET_ATTR_INDEX] = { .type = NLA_U16 },
};

static int DSET_CBFN(domain_set_byindex, struct net *net, struct sock *ctnl,
		     struct sk_buff *skb, const struct nlmsghdr *nlh,
		     const struct nlattr *const attr[],
		     struct netlink_ext_ack *extack)
{
	struct domain_set_net *inst =
		domain_set_pernet(DSET_SOCK_NET(net, ctnl));
	struct sk_buff *skb2;
	struct nlmsghdr *nlh2;
	domain_set_id_t id = DSET_INVALID_ID;
	const struct domain_set *set;
	int ret = 0;

	if (unlikely(protocol_failed(attr) || !attr[DSET_ATTR_INDEX]))
		return -DSET_ERR_PROTOCOL;

	id = domain_set_get_h16(attr[DSET_ATTR_INDEX]);
	if (id >= inst->domain_set_max)
		return -ENOENT;
	set = domain_set(inst, id);
	if (set == NULL)
		return -ENOENT;

	skb2 = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb2)
		return -ENOMEM;

	nlh2 = start_msg(skb2, NETLINK_PORTID(skb), nlh->nlmsg_seq, 0,
			 DSET_CMD_GET_BYINDEX);
	if (!nlh2)
		goto nlmsg_failure;
	if (nla_put_u8(skb2, DSET_ATTR_PROTOCOL, protocol(attr)) ||
	    nla_put_string(skb2, DSET_ATTR_SETNAME, set->name))
		goto nla_put_failure;
	nlmsg_end(skb2, nlh2);

	ret = netlink_unicast(ctnl, skb2, NETLINK_PORTID(skb), MSG_DONTWAIT);
	if (ret < 0)
		return ret;

	return 0;

nla_put_failure:
	nlmsg_cancel(skb2, nlh2);
nlmsg_failure:
	kfree_skb(skb2);
	return -EMSGSIZE;
}

static const struct nfnl_callback domain_set_netlink_subsys_cb[DSET_MSG_MAX] = {
	[DSET_CMD_NONE] =
		{
			.call = domain_set_none,
			.attr_count = DSET_ATTR_CMD_MAX,
		},
	[DSET_CMD_CREATE] =
		{
			.call = domain_set_create,
			.attr_count = DSET_ATTR_CMD_MAX,
			.policy = domain_set_create_policy,
		},
	[DSET_CMD_DESTROY] =
		{
			.call = domain_set_destroy,
			.attr_count = DSET_ATTR_CMD_MAX,
			.policy = domain_set_setname_policy,
		},
	[DSET_CMD_FLUSH] =
		{
			.call = domain_set_flush,
			.attr_count = DSET_ATTR_CMD_MAX,
			.policy = domain_set_setname_policy,
		},
	[DSET_CMD_RENAME] =
		{
			.call = domain_set_rename,
			.attr_count = DSET_ATTR_CMD_MAX,
			.policy = domain_set_setname2_policy,
		},
	[DSET_CMD_SWAP] =
		{
			.call = domain_set_swap,
			.attr_count = DSET_ATTR_CMD_MAX,
			.policy = domain_set_setname2_policy,
		},
	[DSET_CMD_LIST] =
		{
			.call = domain_set_dump,
			.attr_count = DSET_ATTR_CMD_MAX,
			.policy = domain_set_setname_policy,
		},
	[DSET_CMD_SAVE] =
		{
			.call = domain_set_dump,
			.attr_count = DSET_ATTR_CMD_MAX,
			.policy = domain_set_setname_policy,
		},
	[DSET_CMD_ADD] =
		{
			.call = domain_set_uadd,
			.attr_count = DSET_ATTR_CMD_MAX,
			.policy = domain_set_adt_policy,
		},
	[DSET_CMD_DEL] =
		{
			.call = domain_set_udel,
			.attr_count = DSET_ATTR_CMD_MAX,
			.policy = domain_set_adt_policy,
		},
	[DSET_CMD_TEST] =
		{
			.call = domain_set_utest,
			.attr_count = DSET_ATTR_CMD_MAX,
			.policy = domain_set_adt_policy,
		},
	[DSET_CMD_HEADER] =
		{
			.call = domain_set_header,
			.attr_count = DSET_ATTR_CMD_MAX,
			.policy = domain_set_setname_policy,
		},
	[DSET_CMD_TYPE] =
		{
			.call = domain_set_type,
			.attr_count = DSET_ATTR_CMD_MAX,
			.policy = domain_set_type_policy,
		},
	[DSET_CMD_PROTOCOL] =
		{
			.call = domain_set_protocol,
			.attr_count = DSET_ATTR_CMD_MAX,
			.policy = domain_set_protocol_policy,
		},
	[DSET_CMD_GET_BYNAME] =
		{
			.call = domain_set_byname,
			.attr_count = DSET_ATTR_CMD_MAX,
			.policy = domain_set_setname_policy,
		},
	[DSET_CMD_GET_BYINDEX] =
		{
			.call = domain_set_byindex,
			.attr_count = DSET_ATTR_CMD_MAX,
			.policy = domain_set_index_policy,
		},
};

static struct nfnetlink_subsystem domain_set_netlink_subsys __read_mostly = {
	.name = "domain_set",
	.subsys_id = NFNL_SUBSYS_DSET,
	.cb_count = DSET_MSG_MAX,
	.cb = domain_set_netlink_subsys_cb,
};

/* Interface to iptables/ip6tables */

static int domain_set_sockfn_get(struct sock *sk, int optval, void __user *user,
				 int *len)
{
	unsigned int *op;
	void *data;
	int copylen = *len, ret = 0;
	struct net *net = sock_net(sk);
	struct domain_set_net *inst = domain_set_pernet(net);

	if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
		return -EPERM;
	if (optval != SO_DOMAIN_SET)
		return -EBADF;

	if (*len < sizeof(unsigned int))
		return -EINVAL;

	data = vmalloc(*len);
	if (!data)
		return -ENOMEM;
	if (copy_from_user(data, user, *len) != 0) {
		ret = -EFAULT;
		goto done;
	}
	op = data;

	if (*op < DOMAIN_SET_OP_VERSION) {
		/* Check the version at the beginning of operations */
		struct domain_set_req_version *req_version = data;

		if (*len < sizeof(struct domain_set_req_version)) {
			ret = -EINVAL;
			goto done;
		}

		if (req_version->version < DSET_PROTOCOL_MIN) {
			ret = -EPROTO;
			goto done;
		}
	}

	switch (*op) {
	case DOMAIN_SET_OP_VERSION: {
		struct domain_set_req_version *req_version = data;

		if (*len != sizeof(struct domain_set_req_version)) {
			ret = -EINVAL;
			goto done;
		}

		req_version->version = DSET_PROTOCOL;
		if (copy_to_user(user, req_version,
				 sizeof(struct domain_set_req_version)))
			ret = -EFAULT;
		goto done;
	}
	case DOMAIN_SET_OP_GET_BYNAME: {
		struct domain_set_req_get_set *req_get = data;
		domain_set_id_t id;

		if (*len != sizeof(struct domain_set_req_get_set)) {
			ret = -EINVAL;
			goto done;
		}
		req_get->set.name[DSET_MAXNAMELEN - 1] = '\0';
		nfnl_lock(NFNL_SUBSYS_DSET);
		find_set_and_id(inst, req_get->set.name, &id);
		req_get->set.index = id;
		nfnl_unlock(NFNL_SUBSYS_DSET);
		goto copy;
	}
	case DOMAIN_SET_OP_GET_FNAME: {
		struct domain_set_req_get_set_family *req_get = data;
		domain_set_id_t id;

		if (*len != sizeof(struct domain_set_req_get_set_family)) {
			ret = -EINVAL;
			goto done;
		}
		req_get->set.name[DSET_MAXNAMELEN - 1] = '\0';
		nfnl_lock(NFNL_SUBSYS_DSET);
		find_set_and_id(inst, req_get->set.name, &id);
		req_get->set.index = id;
		if (id != DSET_INVALID_ID)
			req_get->family = domain_set(inst, id)->family;
		nfnl_unlock(NFNL_SUBSYS_DSET);
		goto copy;
	}
	case DOMAIN_SET_OP_GET_BYINDEX: {
		struct domain_set_req_get_set *req_get = data;
		struct domain_set *set;

		if (*len != sizeof(struct domain_set_req_get_set) ||
		    req_get->set.index >= inst->domain_set_max) {
			ret = -EINVAL;
			goto done;
		}
		nfnl_lock(NFNL_SUBSYS_DSET);
		set = domain_set(inst, req_get->set.index);
		ret = strscpy(req_get->set.name, set ? set->name : "",
			      DSET_MAXNAMELEN);
		nfnl_unlock(NFNL_SUBSYS_DSET);
		if (ret < 0)
			goto done;
		goto copy;
	}
	default:
		ret = -EBADMSG;
		goto done;
	} /* end of switch(op) */

copy:
	if (copy_to_user(user, data, copylen))
		ret = -EFAULT;

done:
	vfree(data);
	if (ret > 0)
		ret = 0;
	return ret;
}

static struct nf_sockopt_ops so_set __read_mostly = {
	.pf = PF_INET,
	.get_optmin = SO_DOMAIN_SET,
	.get_optmax = SO_DOMAIN_SET + 1,
	.get = domain_set_sockfn_get,
	.owner = THIS_MODULE,
};

static int __net_init domain_set_net_init(struct net *net)
{
	struct domain_set_net *inst;
	struct domain_set **list;

#ifdef HAVE_NET_OPS_ID
	inst = domain_set_pernet(net);
#else
	int err;

	inst = kzalloc(sizeof(struct domain_set_net), GFP_KERNEL);
	if (!inst)
		return -ENOMEM;
	err = net_assign_generic(net, domain_set_net_id, inst);
	if (err < 0)
		goto err_alloc;
#endif
	inst->domain_set_max = max_sets ? max_sets : CONFIG_DOMAIN_SET_MAX;
	if (inst->domain_set_max >= DSET_INVALID_ID)
		inst->domain_set_max = DSET_INVALID_ID - 1;

	list = kvcalloc(inst->domain_set_max, sizeof(struct domain_set *),
			GFP_KERNEL);
	if (!list)
#ifdef HAVE_NET_OPS_ID
		return -ENOMEM;
#else
		goto err_alloc;
#endif
	inst->is_deleted = false;
	inst->is_destroyed = false;
	rcu_assign_pointer(inst->domain_set_list, list);
	return 0;

#ifndef HAVE_NET_OPS_ID
err_alloc:
	kfree(inst);
	return err;
#endif
}

static void __net_exit domain_set_net_exit(struct net *net)
{
	struct domain_set_net *inst = domain_set_pernet(net);

	struct domain_set *set = NULL;
	domain_set_id_t i;

	inst->is_deleted = true; /* flag for domain_set_nfnl_put */

	nfnl_lock(NFNL_SUBSYS_DSET);
	for (i = 0; i < inst->domain_set_max; i++) {
		set = domain_set(inst, i);
		if (set) {
			domain_set(inst, i) = NULL;
			domain_set_destroy_set(set);
		}
	}
	nfnl_unlock(NFNL_SUBSYS_DSET);
	kvfree(rcu_dereference_protected(inst->domain_set_list, 1));
#ifndef HAVE_NET_OPS_ID
	kvfree(inst);
#endif
}

static struct pernet_operations domain_set_net_ops = {
	.init = domain_set_net_init,
	.exit = domain_set_net_exit,
#ifdef HAVE_NET_OPS_ID
	.id = &domain_set_net_id,
	.size = sizeof(struct domain_set_net),
#ifdef HAVE_NET_OPS_ASYNC
	.async = true,
#endif
#endif
};

#ifdef HAVE_NET_OPS_ID
#define REGISTER_PERNET_SUBSYS(s) register_pernet_subsys(s)
#define UNREGISTER_PERNET_SUBSYS(s) unregister_pernet_subsys(s);
#else
#define REGISTER_PERNET_SUBSYS(s)                                              \
	register_pernet_gen_device(&domain_set_net_id, s)
#define UNREGISTER_PERNET_SUBSYS(s)                                            \
	unregister_pernet_gen_device(domain_set_net_id, s);
#endif

static int __init domain_set_init(void)
{
	int ret = REGISTER_PERNET_SUBSYS(&domain_set_net_ops);

	if (ret) {
		pr_err("domain_set: cannot register pernet_subsys.\n");
		return ret;
	}

	ret = nfnetlink_subsys_register(&domain_set_netlink_subsys);
	if (ret != 0) {
		pr_err("domain_set: cannot register with nfnetlink.\n");
		UNREGISTER_PERNET_SUBSYS(&domain_set_net_ops);
		return ret;
	}

	ret = nf_register_sockopt(&so_set);
	if (ret != 0) {
		pr_err("SO_SET registry failed: %d\n", ret);
		nfnetlink_subsys_unregister(&domain_set_netlink_subsys);
		UNREGISTER_PERNET_SUBSYS(&domain_set_net_ops);
		return ret;
	}
	return 0;
}

static void __exit domain_set_fini(void)
{
	nf_unregister_sockopt(&so_set);
	nfnetlink_subsys_unregister(&domain_set_netlink_subsys);

	UNREGISTER_PERNET_SUBSYS(&domain_set_net_ops);
	pr_debug("these are the famous last words\n");
}

module_init(domain_set_init);
module_exit(domain_set_fini);
