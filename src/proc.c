/*
 * proc.c
 *
 *  Created on: Jul 13, 2017
 *      Author: ralph
 */
#include <linux/init.h>
#include <linux/module.h>	/* Specifically, a module */
#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/proc_fs.h>	/* Necessary because we use the proc fs */
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include "proc.h"

#include <linux/hardirq.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/mii.h>
#include <linux/if_vlan.h>
#include <linux/skbuff.h>
#include <linux/ethtool.h>
#include <linux/string.h>
#include <linux/firmware.h>
#include <linux/rtnetlink.h>
#include <asm/unaligned.h>

#include <linux/in.h>
#include <linux/ip.h>          /* struct iphdr */
#include <linux/tcp.h>         /* struct tcphdr */
#include <linux/skbuff.h>

static struct proc_dir_entry *proc_file_entry;
static char *g_msg = NULL;
static int g_temp = 0, g_len = 0, g_len_check = 1;
static bool g_snull_activated = false;

/*
 * The devices
 */
#if SNULL_DYNAMIC
struct net_device **snull_devs;
u_int32_t g_snull_idx = 0;
#else
struct net_device *snull_devs[2];
#endif

/*
 * Transmitter lockup simulation, normally disabled.
 */
static int lockup = 0;
module_param(lockup, int, 0);

static int timeout = SNULL_TIMEOUT;
module_param(timeout, int, 0);

/*
 * Do we run in NAPI mode?
 */
static int use_napi = 0;
module_param(use_napi, int, 0);


int pool_size = 8;
module_param(pool_size, int, 0);

int kylo_open_proc_callback(struct inode * sp_inode, struct file *sp_file)
{
	printk(KERN_INFO "/proc/%s called open\n", g_ver);
	return 0;
}


int kylo_release_proc_callback(struct inode *sp_indoe, struct file *sp_file)
{
	printk(KERN_INFO "/proc/%s called release\n", g_ver);
	return 0;
}


static int kylo_discover_eth_interfaces( void )
{
	int retval = -1;
	struct net_device *dev = NULL;

	read_lock(&dev_base_lock);

	dev = first_net_device( &init_net );
	while( dev )
	{
		printk(KERN_INFO "found [%s]\n", dev->name);
		dev = next_net_device( dev );
		retval = 0;
	}

	read_unlock(&dev_base_lock);

	return(retval);
}


//static struct net_device *g_netdev;
//static struct priv_struct *g_priv;
//static u_int32_t snull_idx = 0;


static void snull_dev_free(struct net_device *dev)
{
	dev_net(dev)->loopback_dev = NULL;
	free_percpu(dev->lstats);
	free_netdev(dev);
}


/*
 * Set up a device's packet pool.
 */
void snull_setup_pool(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);
	int i;
	struct snull_packet *pkt;

	priv->ppool = NULL;
	for (i = 0; i < pool_size; i++) {
		pkt = kmalloc (sizeof (struct snull_packet), GFP_KERNEL);
		if (pkt == NULL) {
			printk (KERN_NOTICE "Ran out of memory allocating packet pool\n");
			return;
		}
		pkt->dev = dev;
		pkt->next = priv->ppool;
		priv->ppool = pkt;
	}
}


void snull_teardown_pool(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);
	struct snull_packet *pkt;

	while ((pkt = priv->ppool)) {
		priv->ppool = pkt->next;
		kfree (pkt);
		/* FIXME - in-flight packets ? */
	}
}


void snull_release_buffer(struct snull_packet *pkt)
{
	unsigned long flags;
	struct snull_priv *priv = netdev_priv(pkt->dev);

	spin_lock_irqsave(&priv->lock, flags);
	pkt->next = priv->ppool;
	priv->ppool = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);
	if (netif_queue_stopped(pkt->dev) && pkt->next == NULL)
		netif_wake_queue(pkt->dev);
}


void snull_enqueue_buf(struct net_device *dev, struct snull_packet *pkt)
{
	unsigned long flags;
	struct snull_priv *priv = netdev_priv(dev);

	spin_lock_irqsave(&priv->lock, flags);
	pkt->next = priv->rx_queue;  /* FIXME - misorders packets */
	priv->rx_queue = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);
}


struct snull_packet *snull_dequeue_buf(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);
	struct snull_packet *pkt;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	pkt = priv->rx_queue;
	if (pkt != NULL)
		priv->rx_queue = pkt->next;
	spin_unlock_irqrestore(&priv->lock, flags);
	return pkt;
}

/*
 * Buffer/pool management.
 */
struct snull_packet *snull_get_tx_buffer(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);
	unsigned long flags;
	struct snull_packet *pkt;

	spin_lock_irqsave(&priv->lock, flags);
	pkt = priv->ppool;
	priv->ppool = pkt->next;
	if (priv->ppool == NULL) {
		printk (KERN_INFO "Pool empty\n");
		netif_stop_queue(dev);
	}
	spin_unlock_irqrestore(&priv->lock, flags);
	return pkt;
}

/*
 * Enable and disable receive interrupts.
 */
static void snull_rx_ints(struct net_device *dev, int enable)
{
	struct snull_priv *priv = netdev_priv(dev);
	priv->rx_int_enabled = enable;
}


/*
 * Open and close
 */


/**
 * @fn int snull_open(struct net_device *dev)
 * @brief Get the driver initialized
 *
 * Called when ifconfig is run, open system resources and turn on hardware
 */
int snull_open(struct net_device *dev)
{
	int ii = 0;


	printk(KERN_INFO "%s: dev %s\n", __FUNCTION__, dev->name);
	/* request_region(), request_irq(), ....  (like fops->open) */

	/*
	 * Assign the hardware address of the board: use "\0SNULx", where
	 * x is 0 or 1. The first byte is '\0' to avoid being a multicast
	 * address (the first byte of multicast addrs is odd).
	 */
	memcpy(dev->dev_addr, "\0SNUL0", ETH_ALEN);
#if 1
	for( ii = 1; ii < MAX_SNULLS; ii++ )
	{
		if (dev == snull_devs[ii]) {
			dev->dev_addr[ETH_ALEN-1]++; /* \0SNULii */
		}
	}
#else
	if (dev == snull_devs[1])
		dev->dev_addr[ETH_ALEN-1]++; /* \0SNUL1 */
#endif
	netif_start_queue(dev);
	return 0;
}


/**
 * @fn int snull_release(struct net_device *dev)
 * @brief Perform reverse steps of \a snull_open
 * @param dev
 * @return
 */
int snull_release(struct net_device *dev)
{
	printk(KERN_INFO "%s: dev %s\n", __FUNCTION__, dev->name);

	/* release ports, irq and such -- like fops->close */
	netif_stop_queue(dev); /* can't transmit any more */

	return 0;
}


/*
 * Configuration changes (passed on by ifconfig)
 */
int snull_config(struct net_device *dev, struct ifmap *map)
{
	printk(KERN_INFO "%s: %s\n", __FUNCTION__, dev->name);

	if (dev->flags & IFF_UP) /* can't act on a running interface */
		return -EBUSY;

	/* Don't allow changing the I/O address */
	if (map->base_addr != dev->base_addr) {
		printk(KERN_WARNING "snull: Can't change I/O address\n");
		return -EOPNOTSUPP;
	}

	/* Allow changing the IRQ */
	if (map->irq != dev->irq) {
		dev->irq = map->irq;
        	/* request_irq() is delayed to open-time */
	}

	/* ignore other fields */
	return 0;
}


/*
 * Receive a packet: retrieve, encapsulate and pass over to upper levels
 */
void snull_rx(struct net_device *dev, struct snull_packet *pkt)
{
	struct sk_buff *skb;
	struct snull_priv *priv = netdev_priv(dev);

	/*
	 * The packet has been retrieved from the transmission
	 * medium. Build an skb around it, so upper layers can handle it
	 */
	skb = dev_alloc_skb(pkt->datalen + 2);
	if (!skb) {
		if (printk_ratelimit())
			printk(KERN_NOTICE "snull rx: low on mem - packet dropped\n");
		priv->stats.rx_dropped++;
		goto out;
	}
	skb_reserve(skb, 2); /* align IP on 16B boundary */
	memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);

	/* Write metadata, and then pass to the receive level */
	skb->dev = dev;
	skb->protocol = eth_type_trans(skb, dev);
	skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */
	priv->stats.rx_packets++;
	priv->stats.rx_bytes += pkt->datalen;
	printk(KERN_INFO "%s: %s: %d octets, proto 0x%04x, room: head %d, tail %d\n",
		__FUNCTION__, dev->name, skb->len, htons(skb->protocol),
		skb_headroom(skb), skb_tailroom(skb));
	netif_rx(skb);
  out:
	return;
}


/*
 * The poll implementation.
 */
static int snull_poll(struct napi_struct *napi, int budget)
{
	int npackets = 0;
	struct sk_buff *skb;
	struct snull_priv *priv = container_of(napi, struct snull_priv, napi);
	struct net_device *dev = priv->dev;
	struct snull_packet *pkt;

	while (npackets < budget && priv->rx_queue) {
		pkt = snull_dequeue_buf(dev);
		skb = dev_alloc_skb(pkt->datalen + 2);
		if (! skb) {
			if (printk_ratelimit())
				printk(KERN_NOTICE "snull: packet dropped\n");
			priv->stats.rx_dropped++;
			snull_release_buffer(pkt);
			continue;
		}
		skb_reserve(skb, 2); /* align IP on 16B boundary */
		memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);
		skb->dev = dev;
		skb->protocol = eth_type_trans(skb, dev);
		skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */
		netif_receive_skb(skb);

        	/* Maintain stats */
		npackets++;
		priv->stats.rx_packets++;
		priv->stats.rx_bytes += pkt->datalen;
		snull_release_buffer(pkt);
	}
	/* If we processed all packets, we're done; tell the kernel and reenable ints */
	if (! priv->rx_queue) {
		napi_complete(napi);
		snull_rx_ints(dev, 1);
		return 0;
	}
	/* We couldn't process everything. */
	return npackets;
}


/*
 * The typical interrupt entry point
 */
static void snull_regular_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	int statusword;
	struct snull_priv *priv;
	struct snull_packet *pkt = NULL;
	/*
	 * As usual, check the "device" pointer to be sure it is
	 * really interrupting.
	 * Then assign "struct device *dev"
	 */
	struct net_device *dev = (struct net_device *)dev_id;
	/* ... and check with hw if it's really ours */

	/* paranoid */
	if (!dev)
		return;

	/* Lock the device */
	priv = netdev_priv(dev);
	spin_lock(&priv->lock);

	/* retrieve statusword: real netdevices use I/O instructions */
	statusword = priv->status;
	priv->status = 0;

	if (statusword & SNULL_RX_INTR) {

		printk(KERN_INFO "%s: RX: dev %s: irq %d, octets %d\n",
			__FUNCTION__, dev->name, irq, priv->tx_packetlen);

		/* send it to snull_rx for handling */
		pkt = priv->rx_queue;
		if (pkt) {
			priv->rx_queue = pkt->next;
			snull_rx(dev, pkt);
		}
	}

	/** Handle Tx Completed Interrupt */
	if (statusword & SNULL_TX_INTR) {

		printk(KERN_INFO "%s: TX: dev %s: irq %d, octets %d\n",
			__FUNCTION__, dev->name, irq, priv->tx_packetlen);

		/* a transmission is over: free the skb */
		priv->stats.tx_packets++;
		priv->stats.tx_bytes += priv->tx_packetlen;
		dev_kfree_skb(priv->skb);
	}

	/* Unlock the device and we are done */
	spin_unlock(&priv->lock);
	if (pkt) snull_release_buffer(pkt); /* Do this outside the lock! */
	return;
}


/*
 * A NAPI interrupt handler.
 */
static void snull_napi_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	int statusword;
	struct snull_priv *priv;

	/*
	 * As usual, check the "device" pointer for shared handlers.
	 * Then assign "struct device *dev"
	 */
	struct net_device *dev = (struct net_device *)dev_id;
	/* ... and check with hw if it's really ours */

	/* paranoid */
	if (!dev)
		return;

	/* Lock the device */
	priv = netdev_priv(dev);
	spin_lock(&priv->lock);

	/* retrieve statusword: real netdevices use I/O instructions */
	statusword = priv->status;
	priv->status = 0;
	if (statusword & SNULL_RX_INTR) {
		snull_rx_ints(dev, 0);  /* Disable further interrupts */
		napi_schedule(&priv->napi);
	}
	if (statusword & SNULL_TX_INTR) {
		/* a transmission is over: free the skb */
		priv->stats.tx_packets++;
		priv->stats.tx_bytes += priv->tx_packetlen;
		dev_kfree_skb(priv->skb);
	}

	/* Unlock the device and we are done */
	spin_unlock(&priv->lock);
	return;
}


/*
 * Transmit a packet (low level interface)
 */
static void snull_hw_tx(char *buf, int len, struct net_device *dev)
{
	/*
	 * This function deals with hw details. This interface loops
	 * back the packet to the other snull interface (if any).
	 * In other words, this function implements the snull behaviour,
	 * while all other procedures are rather device-independent
	 */
	struct iphdr *ih;
	struct net_device *dest;
	struct snull_priv *priv;
	u_int32_t *saddr, *daddr;
	struct snull_packet *tx_buffer;

	printk(KERN_INFO "%s: %s: %d octets\n", __FUNCTION__, dev->name, len);

	/* I am paranoid. Ain't I? */
	if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
		printk("snull: Hmm... packet too short (%i octets)\n",
				len);
		return;
	}

	if (0) { /* enable this conditional to look at the data */
		int i;
		PDEBUG("len is %i\n" KERN_DEBUG "data:",len);
		for (i=14 ; i<len; i++)
			printk(" %02x",buf[i]&0xff);
		printk("\n");
	}
	/*
	 * Ethhdr is 14 bytes, but the kernel arranges for iphdr
	 * to be aligned (i.e., ethhdr is unaligned)
	 */
	ih = (struct iphdr *)(buf+sizeof(struct ethhdr));
	saddr = &ih->saddr;
	daddr = &ih->daddr;

	((u_int8_t *)saddr)[2] ^= 1; /* change the third octet (class C) */
	((u_int8_t *)daddr)[2] ^= 1;

	ih->check = 0;         /* and rebuild the checksum (ip needs it) */
	ih->check = ip_fast_csum((unsigned char *)ih,ih->ihl);

	if (dev == snull_devs[0])
		PDEBUGG("%08x:%05i --> %08x:%05i\n",
				ntohl(ih->saddr),ntohs(((struct tcphdr *)(ih+1))->source),
				ntohl(ih->daddr),ntohs(((struct tcphdr *)(ih+1))->dest));
	else
		PDEBUGG("%08x:%05i <-- %08x:%05i\n",
				ntohl(ih->daddr),ntohs(((struct tcphdr *)(ih+1))->dest),
				ntohl(ih->saddr),ntohs(((struct tcphdr *)(ih+1))->source));

	/*
	 * Ok, now the packet is ready for transmission: first simulate a
	 * receive interrupt on the twin device, then  a
	 * transmission-done on the transmitting device
	 */
	dest = snull_devs[dev == snull_devs[0] ? 1 : 0];
	priv = netdev_priv(dest);
	tx_buffer = snull_get_tx_buffer(dev);
	tx_buffer->datalen = len;
	memcpy(tx_buffer->data, buf, len);
	snull_enqueue_buf(dest, tx_buffer);
	if (priv->rx_int_enabled) {
		priv->status |= SNULL_RX_INTR;
		snull_interrupt(0, dest, NULL);
	}

	priv = netdev_priv(dev);
	priv->tx_packetlen = len;
	priv->tx_packetdata = buf;
	priv->status |= SNULL_TX_INTR;
	if (lockup && ((priv->stats.tx_packets + 1) % lockup) == 0) {
        	/* Simulate a dropped transmit interrupt */
		netif_stop_queue(dev);
		PDEBUG("Simulate lockup at %ld, txp %ld\n", jiffies,
				(unsigned long) priv->stats.tx_packets);
	}
	else
		snull_interrupt(0, dev, NULL);
}


/**
 * @fn int snull_tx(struct sk_buff *skb, struct net_device *dev)
 * @brief Transmit a packet (called by the kernel)
 * @param skb
 * @param dev
 * @return
 */
int snull_tx(struct sk_buff *skb, struct net_device *dev)
{
	int len;
	char *data, shortpkt[ETH_ZLEN];
	struct snull_priv *priv = netdev_priv(dev);


	printk(KERN_INFO "%s: %s: %d octets\n", __FUNCTION__, dev->name, skb->len);
	data = skb->data;
	len = skb->len;
	if (len < ETH_ZLEN) {
		memset(shortpkt, 0, ETH_ZLEN);
		memcpy(shortpkt, skb->data, skb->len);
		len = ETH_ZLEN;
		data = shortpkt;
	}
	dev->trans_start = jiffies; /* save the timestamp */

	/* Remember the skb, so we can free it at interrupt time */
	priv->skb = skb;

	/* actual deliver of data is device-specific, and not shown here */
	snull_hw_tx(data, len, dev);

	return 0; /* Our simple device can not fail */
}


/*
 * Deal with a transmit timeout.
 */
void snull_tx_timeout (struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);

	PDEBUG("Transmit timeout at %ld, latency %ld\n", jiffies,
			jiffies - dev->trans_start);
        /* Simulate a transmission interrupt to get things moving */
	priv->status = SNULL_TX_INTR;
	snull_interrupt(0, dev, NULL);
	priv->stats.tx_errors++;
	netif_wake_queue(dev);
	return;
}


/*
 * Ioctl commands
 */
int snull_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	PDEBUG("ioctl\n");
	return 0;
}


/*
 * Return statistics to the caller
 */
struct net_device_stats *snull_stats(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);
	return &priv->stats;
}


/*
 * This function is called to fill up an eth header, since arp is not
 * available on the interface
 */
int snull_rebuild_header(struct sk_buff *skb)
{
	struct ethhdr *eth = (struct ethhdr *) skb->data;
	struct net_device *dev = skb->dev;

	memcpy(eth->h_source, dev->dev_addr, dev->addr_len);
	memcpy(eth->h_dest, dev->dev_addr, dev->addr_len);
	eth->h_dest[ETH_ALEN-1]   ^= 0x01;   /* dest is us xor 1 */
	return 0;
}


int snull_header(struct sk_buff *skb, struct net_device *dev,
                unsigned short type, const void *daddr, const void *saddr,
                unsigned len)
{
	struct ethhdr *eth = (struct ethhdr *)skb_push(skb,ETH_HLEN);

	eth->h_proto = htons(type);
	memcpy(eth->h_source, saddr ? saddr : dev->dev_addr, dev->addr_len);
	memcpy(eth->h_dest,   daddr ? daddr : dev->dev_addr, dev->addr_len);
	eth->h_dest[ETH_ALEN-1]   ^= 0x01;   /* dest is us xor 1 */
	return (dev->hard_header_len);
}


/*
 * The "change_mtu" method is usually not needed.
 * If you need it, it must be like this.
 */
int snull_change_mtu(struct net_device *dev, int new_mtu)
{
	unsigned long flags;
	struct snull_priv *priv = netdev_priv(dev);
	spinlock_t *lock = &priv->lock;


	printk(KERN_INFO "%s: dev %s: changing MTU from %d to %d\n",
		__FUNCTION__, dev->name, dev->mtu, new_mtu);

	/* check ranges */
	if ((new_mtu < 68) || (new_mtu > 3500))  // ifconfig sn0 mtu 2000 largest tested
		return -EINVAL;
	/*
	 * Do anything you need, and the accept the value
	 */
	spin_lock_irqsave(lock, flags);
	dev->mtu = new_mtu;
	spin_unlock_irqrestore(lock, flags);
	return 0; /* success */
}


static const struct header_ops snull_header_ops = {
	.create  = snull_header,
	//.rebuild = snull_rebuild_header
};

static const struct net_device_ops snull_netdev_ops = {
	.ndo_open            = snull_open,
	.ndo_stop            = snull_release,
	.ndo_start_xmit      = snull_tx,
	.ndo_do_ioctl        = snull_ioctl,
	.ndo_set_config      = snull_config,
	.ndo_get_stats       = snull_stats,
	.ndo_change_mtu      = snull_change_mtu,
	.ndo_tx_timeout      = snull_tx_timeout
};


void snull_ethtool( void )
{
	printk(KERN_INFO "%s: ethtool support\n", __FUNCTION__);
}


/*
 * The init function (sometimes called probe).
 * It is invoked by register_netdev()
 */
void snull_init(struct net_device *dev)
{
	struct snull_priv *priv;

	/*
	 * Make the usual checks: check_region(), probe irq, ...  -ENODEV
	 * should be returned if no device found.  No resource should be
	 * grabbed: this is done on open().
	 */
	printk(KERN_INFO "%s: dev %s\n", __FUNCTION__, dev->name);

	/*
	 * Then, assign other fields in dev, using ether_setup() and some
	 * hand assignments
	 */
	ether_setup(dev); /* assign some of the fields */
	dev->watchdog_timeo = timeout;
	dev->netdev_ops = &snull_netdev_ops;
	dev->header_ops = &snull_header_ops;
	/* keep the default flags, just add NOARP */
	dev->flags           |= IFF_NOARP;
	dev->features        |= NETIF_F_HW_CSUM;
	dev->ethtool_ops    = &snull_ethtool;


	/*
	 * Then, initialize the priv field. This encloses the statistics
	 * and a few private fields.
	 */
	priv = netdev_priv(dev);
	if( use_napi ) {
		netif_napi_add(dev, &priv->napi, snull_poll,2);
	}

	memset(priv, 0, sizeof(struct snull_priv));
	spin_lock_init(&priv->lock);
	snull_rx_ints(dev, 1);		/* enable receive interrupts */
	snull_setup_pool(dev);
}


/*
 * Finally, the module stuff
 */
void snull_cleanup(void)
{
	u_int32_t ii;

	if( !g_snull_activated ) {
		printk(KERN_INFO "%s: snull not actived, nothing to do\n", __FUNCTION__);
		return;
	}

	for( ii = 0; ii < MAX_SNULLS; ii++ )
	{
		if( snull_devs[ii] )
		{
			unregister_netdev(snull_devs[ii]);
			snull_teardown_pool(snull_devs[ii]);
			free_netdev(snull_devs[ii]);
		}
	}

	kfree( snull_devs[ii] );

	g_snull_activated = false;
}


static int kylo_create_eth_interface( void )
{
	int retval = -ENOMEM, result;
	int size;
	int ii = 0;


	if( g_snull_activated ) {
		printk(KERN_WARNING "%s: interfaces already created\n", __FUNCTION__);
		kylo_discover_eth_interfaces();
		return -ENODEV;
	}

	g_snull_activated = true;

	snull_interrupt = use_napi ? snull_napi_interrupt : snull_regular_interrupt;

	/** alloc memory for new device */
	size = sizeof(struct net_device) * MAX_SNULLS;
	snull_devs = kmalloc( size, GFP_KERNEL);
	if( NULL == snull_devs ) {
		printk(KERN_WARNING "FAILED to allocate %d  bytes\n", size);
		return(retval);
	}

	/* Allocate the devices */
#if SNULL_DYNAMIC
	for( ii = 0; ii < MAX_SNULLS; ii++ )
	{
		snull_devs[ii] = alloc_netdev( sizeof(struct snull_priv), "sn%d", NET_NAME_UNKNOWN, snull_init );
		/* TODO: need to check for memory allocation failure */
		printk(KERN_INFO "%3d) alloc_netdev: %d bytes, %s\n",
			ii, sizeof(struct snull_priv), snull_devs[ii]->name);

	}

	retval = 0;

#else
	snull_devs[0] = alloc_netdev( sizeof(struct snull_priv), "sn%d", NET_NAME_UNKNOWN, snull_init );
	snull_devs[1] = alloc_netdev( sizeof(struct snull_priv), "sn%d", NET_NAME_UNKNOWN, snull_init );


	if (snull_devs[0] == NULL || snull_devs[1] == NULL) {
		goto out;
	}
#endif

#if 1
	retval = -ENODEV;
	/**
	 * Registering the netdev should be the very last initialization step
	 */
	for( ii = 0; ii < MAX_SNULLS;  ii++)
		if( (result = register_netdev(snull_devs[ii])) )
			printk(KERN_INFO "snull: error %i registering device \"%s\"\n",
				result, snull_devs[ii]->name);
		else {
			retval = 0;
		}
#endif

out:
	if( retval ) {
		printk(KERN_WARNING "Some error occured...cleanup and quit\n");
		snull_cleanup();
	}

	return( retval );
}


/**
 * @fn
 * @brief
 * @param filp
 * @param buf
 * @param count
 * @param offp
 * @return
 */
static int kylo_write_proc_callback(struct file *sp_file, const char __user *buf, size_t count, loff_t *offset)
{
	int n = 0;
	int retval;

	printk(KERN_INFO "%s: count %d\n", __FUNCTION__, count);

	g_len = count;
	n = copy_from_user(g_msg, buf, g_len);

	//for(ii = 0; ii < count; ii++ ) {
	//	printk(KERN_INFO "%3d) %02x:", ii, g_msg[ii]);
	//}
	//printk(KERN_INFO "\n");

	g_msg[count-1] = 0;  /// strip off the '\n'

	if( 0 == strncmp(g_msg, "1", MSGSIZE) ) {
		printk(KERN_INFO "1 received\n");
		retval = kylo_discover_eth_interfaces();
	}
	else if( 0 == strncmp(g_msg, "2", MSGSIZE) ) {
		printk(KERN_INFO "2 received\n");
		retval = kylo_create_eth_interface();
	}
	else {
		/** Invalid input */
		printk(KERN_CRIT "INVALID input %s (n = %d)\n", g_msg, n);
	}
	return(g_len);
}


/**
 * @fn
 * @brief
 * @param sp_file
 * @param buf
 * @param count
 * @param offset
 * @return
 */
int kylo_read_proc_callback( struct file *sp_file, char __user *buf, size_t count, loff_t *offset )
{
	if(g_len_check) {
		g_len_check = 0;
	}
	else {
		g_len_check = 1;
		return 0;
	}

	printk(KERN_INFO "proc called read %d\n", count);
	copy_to_user( buf, g_msg, g_len);

	return(g_len);
}


static const struct file_operations proc_fops = {
 .owner = THIS_MODULE,
 .open  = kylo_open_proc_callback,
 .read  = kylo_read_proc_callback,
 .write = kylo_write_proc_callback,
 .release = kylo_release_proc_callback,
};


/**
 * @fn
 * @brief
 * @return
 */
int kylo_create_proc_entry(void)
{
	g_len = 0; g_temp = 0;
	g_msg = NULL;

	proc_file_entry = proc_create(g_ver, 0666, NULL, &proc_fops);
	if(proc_file_entry == NULL) {
		return -ENOMEM;
	}

	g_msg = (char *)kmalloc( MSGSIZE, GFP_KERNEL );
	if( NULL == g_msg ) {
		printk(KERN_CRIT "FAILED to allocate %d bytes\n", MSGSIZE);
	    return -ENOMEM;
	}

	return(0);
}


/**
 * @fn
 * @brief
 * @return
 */
int kylo_remove_proc_entry(void)
{
	remove_proc_entry( g_ver, NULL );

	if( g_msg == NULL ) {
	    return -ENOMEM;
	}

	kfree(g_msg);

	return(0);
}
