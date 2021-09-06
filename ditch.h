/*
 * Copyright (c) 2021 Zenghui Zhai <singchia@163.com>
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

enum {
    IFLA_DITCH_UNSPEC,
    __IFLA_DITCH_MAX,
};

#define IFLA_DITCH_MAX (__IFLA_DITCH_MAX - 1)

/**
 *	struct ditch_pcpu_stats - DITCH percpu stats
 *	@rx_packets: number of received packets
 *	@rx_bytes: number of received bytes
 *	@rx_multicast: number of received multicast packets
 *	@tx_packets: number of transmitted packets
 *	@tx_bytes: number of transmitted bytes
 *	@syncp: synchronization point for 64bit counters
 *	@rx_errors: number of rx errors
 *	@tx_dropped: number of tx dropped packets
 */
struct ditch_pcpu_stats {
	u64                     rx_packets;
	u64                     rx_bytes;
	u64                     rx_multicast;
	u64                     tx_packets;
	u64                     tx_bytes;
	u32                     rx_errors;
	u32                     tx_dropped;
	struct u64_stats_sync	syncp;
};

#define DITCH_HASH_SIZE (1<<BITS_PER_BYTE)

struct ditch_port {
    struct net_device   *dev;
    struct hlist_head   ditch_hash[DITCH_HASH_SIZE];
    struct list_head    ditchs;
    int                 count;
	struct rcu_head     rcu;
};

#define DITCH_MAC_FILTER_SIZE (1 << BITS_PER_BYTE)

struct ditch_dev {
    struct net_device   *dev;
    struct hlist_node   hlist;
    struct list_head    list;
    struct ditch_port   *port;
    struct net_device   *lowerdev;
    struct ditch_pcpu_stats __percpu *pcpu_stats;

    DECLARE_BITMAP(ditch_mac_filter, DITCH_MAC_FILTER_SIZE);
    u16                 flags;
};

#endif /* _LINUX_DITCH_H */
