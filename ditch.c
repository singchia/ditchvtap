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
#include <linux/if_arp.h>
#include <linux/notifier.h>

extern const struct net_device_ops ditch_netdev_ops;
extern const struct header_ops ditch_hard_header_ops;
extern const struct ethtool_ops ditch_ethtool_ops;

/* ditch port */
static struct ditch_port *ditch_port_get_rcu(const struct net_device *dev)
{
    return rcu_dereference(dev->rx_handler_data);
}

static struct ditch_port *ditch_port_get_rtnl(const struct net_device *dev)
{
    return rtnl_dereference(dev->rx_handler_data);
}

/* rx stats */
static inline void ditch_count_rx(const struct ditch_dev *ditch,
                unsigned int len, bool success, bool multicast)
{
    if (likely(success)) {
        struct ditch_pcpu_stats *pcpu_stats;
        pcpu_stats = this_cpu_ptr(ditch->pcpu_stats);
        u64_stats_update_begin(&pcpu_stats->syncp);
        pcpu_stats->rx_packets++;
        pcpu_stats->tx_bytes += len;
        if (multicast)
            pcpu_stats->rx_multicast++;
        u64_stats_update_end(&pcpu_stats->syncp);
    } else {
        this_cpu_inc(ditch->pcpu_stats->rx_errors);
    }
}

/* broadcast one */
static int ditch_broadcast_one(struct sk_buff *skb,
                    const struct ditch_dev *ditch,
                    const struct ethhdr *eth)
{
    if (!skb)
        return NET_RX_DROP;

    struct net_device *dev = ditch->dev;
    skb->dev = dev;
    if (ether_addr_euqal_64bits(eth->h_dest, dev->broadcast))
        skb->pkt_type = PACKET_BROADCAST;
    else
        skb->pkt_type = PACKET_MULTICAST;

    return netif_rx(skb);
}

/* broadcast */
static void ditch_broadcast(struct sk_buff *skb,
                    const struct ditch_port *port)
{
    const struct ethhdr *eth = eth_hdr(skb);
    const struct ditch_dev *ditch;
    struct sk_buff *nskb;
    int err;
    unsigned int i;
    if (skb->protocol == htons(ETH_P_PAUSE))
        return;

    for (i = 0; i < DITCH_HASH_SIZE; i++) {
        hlist_for_each_entry_rcu(ditch, &port->ditch_hash[i], hlist) {
            nskb = skb_clone(skb, GFP_ATOMIC);
            err = ditch_broadcast_one(nskb, ditch, eth);
            ditch_count_rx(ditch, skb->len + ETH_HLEN,
                    err == NET_RX_SUCCESS, 1);
        }
    }
}

/* netif_receive_skb */
static rx_handler_result_t ditch_handle_frame(struct sk_buff **pskb)
{
    struct ditch_port *port;
    struct sk_buff *skb = *pskb;
    const struct ethhdr *eth = eth_hdr(skb);
    const struct ditch_dev *ditch;
    const struct ditch_dev *src;
	struct net_device *dev;
    unsigned int len = 0;
    int ret = NET_RX_DROP;

    port = ditch_port_get_rcu(skb->dev);
    if (is_multicast_ether_addr(eth->h_dest)) {
        eth = eth_hdr(skb);
        src = ditch_hash_lookup(port, eth->h_source);
        if (!src && (skb->dev->flags & (IFF_ALLMULTI | IFF_PROMISC)))
            ditch_broadcast(skb, port);
        return RX_HANDLER_PASS;
    }

    ditch = ditch_rss_lookup(port, skb);
    dev = ditch->dev;
    if (unlikely(!(dev->flags & IFF_UP))) {
        kfree_skb(skb);
        return RX_HANDLER_CONSUMED;
    }
    len = skb->len + ETH_ELEN;
    skb = skb_share_check(skb, GFP_ATOMIC);
    if (!skb)
        goto out;

    skb->dev = dev;
    skb->pkt_type = PACKET_HOST;
    ret = netif_rx(skb);

out:
    ditch_count_rx(ditch, len, ret == NET_RX_SUCCESS, 0);
    return RX_HANDLER_CONSUMERD;
}

/* ditch port */
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
    unsigned int i;
    int err;

    if (dev->type != ARPHRD_ETHER || dev->flags & IFF_LOOPBACK)
        return -EINVAL;

    port = kzalloc(sizeof(*port), GPL_KERNEL);
    if (port == NULL)
        return -ENOMEM;

    port->dev = dev;
    INIT_LIST_HEAD(&port->ditches);
    for (i = 0; i < DITCH_MAC_FILTER_SIZE; i++)
        INIT_HLIST_HEAD(&port->ditch_hash[i]);

    err = netdev_rx_handler_register(dev, ditch_handle_frame, port);
    if (err)
        kfree(port);
    else
        dev->priv_flags |= IFF_DITCH_PORT;
    return err;
}

static int ditch_port_destroy(struct net_device *dev)
{
    struct ditch_port *port = ditch_port_get_rtnl(dev);
    dev->priv_flags &= ~IFF_DITCH_PORT;
    netdev_rx_handler_unregister(dev);
    kfree_rcu(port, rcu);
}

/* netlink ops detail */
static void ditch_setup(struct net_device *dev)
{
    ether_setup(dev);

    dev->priv_flags &= ~(IFF_XMIT_DST_RELEASE | IFF_TX_SKB_SHARING);
    dev->priv_flags |= IFF_UNICAST_FLT;
    dev->netdev_ops = &ditch_netdev_ops;
    dev->header_ops = &ditch_hard_header_ops;
    dev->ethtool_ops = &ditch_ethtool_ops;
    dev->destructor = free_netdev;
    dev->tx_queue_len = 0;
}

static int ditch_newlink(struct net *src_net, struct net_device *dev,
                    struct nlattr *tb[], struct nlattr *data[])
{
    struct ditch_dev *ditch = newdev_priv(dev);
    struct ditch_port *port;
    struct net_device *lowerdev;
    int err;

    if (!tb[IFLA_LINK])
        return -EINVAL;

    lowerdev = __dev_get_by_index(src_net, nla_get_u32(tb[IFLA_LINK]));
    if (lowerdev == NULL)
        return -ENODEV;

    /*
     * When creating ditches on top of other ditches,
     * use the real device as the lowerdev.
     */
    if (lowerdev->rtnl_link_ops == dev->rtnl_link_ops) {
        struct ditch_dev *lowerditch = netdev_priv(lowerdev);
        lowerdev = lowerditch->lowerdev;
    }

    if (!tb[IFLA_MTU])
        dev->mtu = lowerdev->mtu;
    else if (dev->mtu > lowerdev->mtu)
        return -EINVAL;

    if (!tb[IFLA_ADDRESS])
        eth_hw_addr_random(dev);

    if (!ditch_port_exists(lowerdev)) {
        err = ditch_port_create(lowerdev);
        if (err < 0)
            return err;
    }
    port = ditch_port_get_rtnl(lowerdev);

    /* ditch_dev register */
    ditch->lowerdev = lowerdev;
    ditch->dev      = dev;
    ditch->port     = port;

    err = netdev_upper_dev_link(lowerdev, dev);
    if (err)
        goto destroy_port;
    
    port->count += 1;
    err = register_netdevice(dev);
    if (err < 0)
        goto upper_dev_unlink;

    list_add_tail_rcu(&ditch->list, &port->ditches);
    netif_stacked_transfer_operstate(lowerdev, dev);
    return 0;

upper_dev_unlink:
    netdev_upper_dev_unlink(lowerdev, dev);
destroy_port:
    port->count -= -1;
    if (!port->count)
        ditch_port_destroy(lowerdev);

    return err;
}

static void ditch_dellink(struct net_device *dev, struct list_head *head)
{
    struct ditch_dev *ditch = netdev_priv(dev);
    struct ditch_port *port = ditch->port;
    list_del_rcu(&ditch->ditches);
    unregister_netdevice_queue(dev, head);
    netdev_upper_dev_unlink(ditch->lowerdev, dev);
    port->count -= 1;
    if (!port->count)
        ditch_port_destroy(port->dev);
}

static int ditch_validate(struct nlattr *tb[], struct nlattr *data[])
{
    if (tb[IFLA_ADDRESS]) {
        if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
            return -EINVAL;
        if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
            return -EADDRNOTAVAIL;
    }
    return 0;
}

static const struct nla_policy ditch_policy[IFLA_DITCH_MAX + 1] = {
    [IFLA_DITCH_FLAGS] = { .type = NLA_U16 },
};

static size_t ditch_get_size(const struct net_device *dev)
{
    return (0 + nla_total_size(2));
}

static int ditch_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
    struct ditch_dev *ditch = netdev_priv(dev);

    if (nla_put_u16(skb, IFLA_DITCH_FLAGS, ditch->flags))
        goto nla_put_failure;
    return 0;

nla_put_failure:
    return -EMSGSIZE;
}

/* netlink ops */
static struct rtnl_link_ops ditch_link_ops = {
    .kind       = "ditch",
    .setup      = ditch_setup;
    .newlink    = ditch_newlink;
    .dellink    = ditch_dellink;
    .priv_size  = sizeof(ditch_dev);
    .validate   = ditch_validate;
    .policy     = ditch_policy;
    .get_size   = ditch_get_size;
    .fill_info  = ditch_fill_info;
};

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
    
    port = ditch_port_get_rtnl(dev);
    
    switch (event) {
    case NETDEV_CHANGE:
        list_for_each_entry(ditch, &port->ditches, list)
            netif_stacked_transfer_operstate(ditch->lowerdev,
                            ditch->dev);
        break;
    case NETDEV_FEAT_CHANGE:
        list_for_each_entry(ditch, &port->ditches, list) {
            ditch->dev->features = dev->features & DITCH_FEATURES;
            ditch->dev->gso_max_size = dev->gso_max_size;
            netdev_features_change(ditch->dev);
        }
        break;
    case NETDEV_UNREGISTER:
		/* twiddle thumbs on netns device moves */
        if (dev->reg_state != NETREG_UNREGISTRING)
            break;

        list_for_each_entry(ditch, &port->ditches, list) {
            ditch->dev->rtnl_link_ops->dellink(ditch->dev, &list_kill);
        }
        break;
    case NETDEV_PRE_TYPE_CHANGE:
        return NOTIFY_BAD;
    }
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

    err = rtnl_link_register(&ditch_link_ops);
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
MODULE_ALIAS_RTNL_LINK("ditchvtap");
