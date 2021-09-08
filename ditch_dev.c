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

    err = dev_uc_add(lowerdev, dev->dev_addr);
    if (err < 0)
        goto out;

    if (dev->flags & IFF_ALLMULTI) {
        err = dev_set_allmulti(lowerdev, 1);
        if (err < 0)
            goto del_unicast;
    }

out:
    return err;
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
    //.ndo_get_stats64        = ditch_get_stats64,
    .ndo_validate_addr      = ditch_validate_addr,
    .ndo_vlan_rx_add_vid    = ditch_vlan_rx_add_vid,
    .ndo_vlan_rx_kill_vid   = ditch_vlan_rx_kill_vid,
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
