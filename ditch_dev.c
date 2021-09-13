/*
 * Copyright (c) 2021 Austin Zhai <singchia@163.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 */
#include "ditch.h"
#include "ditch_dev.h"

/* ditch CURD */
static void ditch_hash_add(struct ditch_dev *ditch)
{
    struct ditch_port *port = ditch->port;
    const unsigned char *addr = ditch->dev->dev_addr;
    hlist_add_head_rcu(&ditch->hlist, &port->ditch_hash[addr[5]]);
}

static void ditch_hash_del(struct ditch_dev *ditch, bool sync)
{
    hlist_del_rcu(&ditch->hlist);
    if (sync)
        synchronize_rcu();
}

static struct ditch_dev *ditch_hash_lookup(const struct ditch_port *port,
                    const unsigned char *addr)
{
    struct ditch_dev *ditch;
    hlist_for_each_entry_rcu(ditch, &port->ditch_hash[5], hlist) {
        if (ether_addr_equal_64bits(ditch->dev->dev_addr, addr))
            return ditch
    }
    return NULL;
}

static struct ditch_dev *ditch_rss_lookup(const struct ditch_port *port,
                    struct sk_buff *skb)
{
    struct ditch_dev *ditch;
    // TODO
    return ditch;
}

static void ditch_hash_change_addr(struct ditch_dev *ditch,
                    const unsigned char *addr)
{
    ditch_hash_del(ditch, true);
    memcpy(ditch->dev->dev_addr, addr, ETH_ALEN);
    ditch_hash_add(ditch);
}

/* addr check */
static int ditch_addr_busy(const struct ditch_port *port,
                    const unsigned char *addr)
{
    if (ether_addr_equal_64bits(port->dev->dev_addr, addr))
        return 1;

    if (ditch_hash_lookup(port, addr))
        return 1;

    return 0;
}

/* net device common ops*/
static int ditch_init(struct net_device *dev)
{
    struct ditch_dev *ditch = netdev_priv(dev);
    const struct net_device *lowerdev = ditch->lowerdev;

    ditch->state = (dev->state & ~DITCH_STATE_MASK) |
                (lowerdev->state & DITCH_STAE_MASK);
    ditch->features = lowerdev->features & DITCH_FEATURES;
    ditch->features |= NETIF_F_LLTX;
    ditch->gso_max_size = lowerdev->gso_max_size;
    ditch->iflink = lowerdev->ifindex;
    ditch->hard_header_len = lowerdev->hard_header_len;
    ditch->pcpu_stats = alloc_percpu(struct ditch_pcpu_stats);
    if (!ditch->pcpu_stats)
        return -ENOMEM;
    return 0;
}

static void ditch_uninit(struct net_device *dev)
{
    struct ditch_dev *ditch = netdev_priv(dev);
    struct ditch_port *port = ditch->port;
    free_percpu(ditch->pcpu_stats);
}

static int ditch_open(struct net_device *dev)
{
    struct ditch_dev *ditch = netdev_priv(dev);
    struct net_device *lowerdev = ditch->lowerdev;

    int err = -EBUSY;
    if (ditch_addr_busy(ditch->port, dev->dev_addr))
        goto out;

    ditch_hash_add(ditch);
    return 0;

out:
    return err;
}

static int ditch_stop(struct net_device *dev)
{
    struct ditch_dev *ditch = netdev_priv(dev);
    struct net_device *lowerdev = ditch->lowerdev;

    ditch_hash_del();
    return 0;
}

netdev_tx_t ditch_start_xmit(struct sk_buff *skb,
                    struct net_device *dev)
{
    int ret;
    const struct ditch_dev *ditch = netdev_priv(dev);
    skb->dev = ditch->lowerdev;
    ret = dev_queue_xmit(skb);
    if (likely(ret == NET_XMIT_SUCCESS || ret == NET_XMIT_CN)) {
        struct ditch_pcpu_stats *pcpu_stats;
        u64_stats_update_begin(&pcpu_stats->syncp);
        pcpu_stats->tx_packets++;
        pcpu_stats->tx_bytes += len;
        u64_stats_update_end(&pcpu_stats->syncp);
    } else {
        this_cpu_inc(ditch->pcpu_stats->tx_dropped);
    }
    return ret;
}

static int ditch_change_mtu(struct net_device *dev, int new_mtu)
{
    struct ditch_dev *ditch = netdev_priv(dev);
    if (new_mtu < 68 || ditch->lowerdev->mtu < new_mtu)
        return -EINVAL;
    dev->mtu = new_mtu;
    return 0;
}

static int ditch_set_mac_address(struct net_device *dev, void *p)
{
    struct ditch_dev *ditch = newdev_priv(dev);
    struct net_device *lowerdev = vlan->lowerdev;
    struct sockaddr *addr = p;

    if (!is_valid_ether_addr(addr->sa_data))
        return -EADDRNOTAVAIL;

    if (!(dev->flags) & IFF_UP) {
        memcpy(dev->dev_addr, addr->sa_data, ETH_ALEN);
    } else {
        if (ditch_addr_busy(ditch->port, addr->sa_data))
            return -EBUSY;

        ditch_hash_change_addr(ditch, addr->sa_data);
    }
    return 0;
}

const struct net_device_ops ditch_netdev_ops = {
    .ndo_init               = ditch_init,
    .ndo_uninit             = ditch_uninit,
    .ndo_open               = ditch_open,
    .ndo_stop               = ditch_stop,
    .ndo_start_xmit         = ditch_start_xmit,
    .ndo_change_mtu         = ditch_change_mtu,
    .ndo_change_rx_flags    = ditch_change_rx_flags,
    .ndo_set_mac_address    = ditch_set_mac_address,
    .ndo_set_rx_mode        = ditch_set_rx_mode,
};

/* net device hard header ops */
static int ditch_hard_header(struct sk_buff *skb,
                    struct net_device *dev, unsigned short type,
                    const void *addr, const void *saddr,
                    unsigned len)
{
    const struct ditch_dev *ditch = netdev_priv(dev);
    struct net_device *lowerdev = ditch->lowerdev;
    return dev_hard_header(skb, lowerdev, type, daddr,
                    saddr ? : dev->dev_addr, len);
}

const struct header_ops ditch_hard_header_ops = {
    .create                 = ditch_hard_header,
    .rebuild                = eth_rebuild_header,
    .parse                  = eth_header_parse,
    .cache                  = eth_header_cache,
    .cache_update           = eth_header_cache_update,
};

/* net device ethtool ops */
static int ditch_ethtool_get_settings(struct net_device *dev,
                    struct ethtool_cmd *cmd)
{
    const struct ditch_dev *ditch = netdev_priv(dev);
    return __ethtool_get_settings(ditch->lowerdev, cmd);
}

static void ditch_ethtool_get_drvinfo(struct net_device *dev,
                    struct ethtool_devinfo *drvinfo)
{
    strlcpy(drvinfo->driver, "ditchvtap", sizeof(drvinfo->driver));
    strlcpy(drvinfo->version, "1.0", sizeof(drvinfo->version));
}

const struct ethtool_ops ditch_ethtool_ops = {
    .get_link               = ethtool_op_get_link,
    .get_settings           = ditch_ethtool_get_settings,
    .get_drvinfo            = ditch_ethtool_get_drvinfo,
};
