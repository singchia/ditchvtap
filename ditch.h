/*
 * Copyright (c) 2021 Austin Zhai <singchia@163.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 */
#ifndef _LINUX_DITCH_H
#define _LINUX_DITCH_H

#include <linux/netdevice.h>
#include <linux/version.h>
#include <linux/types.h>

#define IFF_DITCH_PORT 1<<21
#define ditch_port_exists(dev) (dev->priv_flags & IFF_DITCH_PORT)

/* ditch device flags */
enum {
    IFLA_DITCH_UNSPEC,
    IFLA_DITCH_FLAGS,
    __IFLA_DITCH_MAX,
};

#define IFLA_DITCH_MAX (__IFLA_DITCH_MAX - 1)
#define DITCH_HASH_SIZE (1<<BITS_PER_BYTE)

struct ditch_port {
    struct net_device   *dev;
    struct hlist_head   ditch_hash[DITCH_HASH_SIZE];
    struct list_head    ditches;
    int                 count;
	struct rcu_head     rcu;
};

#endif /* _LINUX_DITCH_H */
