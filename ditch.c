/*
 * Copyright (c) 2021 Zenghui Zhai <singchia@163.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 */
#include "ditch.h"
#include <linux/if_arp.h>
#include <linux/notifier.h>

static struct ditch_port *ditch_port_get_rcu(const struct net_device *dev)
{
    return rcu_dereference(dev->rx_handler_data);
}

static struct ditch_port *ditch_port_get_rtnl(const struct net_device *dev)
{
    return rtnl_dereference(dev->rx_handler_data);
}

static int ditch_port_create(struct net_device *dev)
{
    struct ditch_port *port;
    int err;

    if (dev->type != ARPHDR_ETHER || dev->flags & IFF_LOOPBACK)
        return -EINVAL;
    
    port = kalloc(sizeof(*port), GFP_KERNEL);
    if (port == NULL)
        return -ENOMEM;
    
    port->dev = dev;
    // TODO add rss hash function

    err = netdev_rx_handler_register(dev, ditch_handle_frame, port);
    if (err)
        kfree(port);
    else
        dev->priv_flags |= IFF_DITCH_PORT;
    return err;
}

static void ditch_port_destroy(struct net_device *dev)
{
    struct ditch_port *port = rsiface_port_get_rtnl(dev);

    dev->priv_flags &= ~IFF_DITCH_PORT;
    netdev_rx_handler_unregister();
}

static u32 ditch_hash_mix(const struct ditch_dev *ditch)
{
	return (u32)(((unsigned long)ditch) >> L1_CACHE_SHIFT);
}

static unsigned int ditch_mac_hash(const struct ditch_dev *ditch,
                const unsigned char *addr)
{
    u32 val = _get_unaligned_cpu32(addr + 2);
    val ^= ditch_hash_mix(ditch);
    return hash_32(val, BITS_PER_BYTE);
}

static inline void ditch_count_rx(const struct ditch_dev *ditch,
                unsigned int len, bool success, bool multicast)

/* netlink register */
int ditch_link_register(struct rtnl_link_ops *ops)
{
    ops->priv_size  = sizeof(ditch_dev);
    ops->validata   = ditch_validate;
    ops->policy     = ditch_policy;
    ops->changelink = ditch_changelink;
    ops->get_size   = ditch_get_size;
    ops->fill_info  = ditch_fill_info;
    ops->maxtype    = IFLA_DITCH_MAX;

    return rtnl_link_register(ops);
};
EXPORT_SYMBOL_GPL(ditch_link_register);

#define ditch_port_exists(dev) (dev->priv_flags & IFF_DITCH_PORT)

/* notification from notifier */
static int ditch_device_event(struct notifier_block *unused,i
                unsigned long event, void *ptr)
{
    struct net_device *dev = ptr;
    struct ditch_dev *ditch, *next;
    struct ditch_port *port;
    LIST_HEAD(list_kill);

    if (!ditch_port_exists(dev))
        return NOTIFY_DONE;
}

/* notifier */
static struct notifier_block ditch_notifier_block __read_mostly = {
    .notifier_call = ditch_device_event;
};

/* init */
static int __init ditch_init_module(void)
{
    int err;

    register_netdevice_notifier(&ditch_notifier_block);

    err = ditch_link_register(&ditch_link_ops);
    if (err < 0)
        goto register_err;
    return 0;
register_err:
    unregister_netdevice_notifier(&ditch_notifier_block);
    return err;
}

static void __exit ditch_clecnup_module(void)
{
    rtnl_link_unregister(&ditch_link_ops);
    unregister_netdevice_notifier(&ditch_notifier_block);
}

module_init(ditch_init_module);
module_exit(ditch_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Austin Zhai <singchia@163.com>");
MODULE_DESCRIPTION("Driver for receive side scalings");
MODULE_ALIAS_RTNL_LINK("ditch");
