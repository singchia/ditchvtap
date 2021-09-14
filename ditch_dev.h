/*
 * Copyright (c) 2021 Austin Zhai <singchia@163.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 */
#ifndef _LINUX_DITCH_DEV_H
#define _LINUX_DITCH_DEV_H

#include "ditch.h"
#include <linux/netdev_features.h>
#include <linux/netdevice.h>

#define DITCH_FEATURES \
	(NETIF_F_SG | NETIF_F_HIGHDMA | NETIF_F_FRAGLIST | \
	 NETIF_F_GSO | NETIF_F_TSO | NETIF_F_UFO | NETIF_F_GSO_ROBUST | \
	 NETIF_F_TSO_ECN | NETIF_F_TSO6 | NETIF_F_GRO | NETIF_F_RXCSUM | \
	 NETIF_F_HW_VLAN_CTAG_FILTER | NETIF_F_HW_VLAN_STAG_FILTER)

#define DITCH_STATE_MASK \
	((1<<__LINK_STATE_NOCARRIER) | (1<<__LINK_STATE_DORMANT))

/**
 *	struct ditch_pcpu_stats - DITCH percpu stats
 *	@rx_packets: number of received packets
 *	@rx_bytes: number of received bytes
 *	@rx_multicast: number of received multicast packets
 *	@tx_packets: number of transmitted packets
 *	@tx_bytes: number of transmitted bytes
 *	@rx_errors: number of rx errors
 *	@tx_dropped: number of tx dropped packets
 *	@syncp: synchronization point for 64bit counters
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

#define DITCH_MAC_FILTER_SIZE (1 << BITS_PER_BYTE)

struct ditch_dev {
    struct net_device   *dev;
    struct hlist_node   hlist;
    struct list_head    list;
    struct ditch_port   *port;
    struct net_device   *lowerdev;
    struct ditch_pcpu_stats __percpu *pcpu_stats;

    DECLARE_BITMAP(ditch_mac_filter, DITCH_MAC_FILTER_SIZE);
    u16 flags;
};

struct ditch_dev *ditch_hash_lookup(const struct ditch_port *port,
                    const unsigned char *addr);

struct ditch_dev *ditch_rss_lookup(const struct ditch_port *port,
                    struct sk_buff *skb);

#endif /* _LINUX_DITCH_DEV_H */
