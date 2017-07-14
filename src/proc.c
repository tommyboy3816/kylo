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

static struct proc_dir_entry *proc_file_entry;
static char *g_msg = NULL;
static int g_temp = 0, g_len = 0, g_len_check = 1;


typedef struct snull_priv {
	int a;
	char b;
	short int c;
} SNULL_PRIV_T;

int kylo_open_proc_callback(struct inode * sp_inode, struct file *sp_file)
{
	printk(KERN_INFO "/proc/%s called open\n", PROCFS_NAME);
	return 0;
}


int kylo_release_proc_callback(struct inode *sp_indoe, struct file *sp_file)
{
	printk(KERN_INFO "/proc/%s called release\n", PROCFS_NAME);
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


static struct net_device *g_netdev;
static struct priv_struct *g_priv;

struct nic *nic;
static u_int32_t snull_idx = 0;


static void snull_dev_free(struct net_device *dev)
{
	dev_net(dev)->loopback_dev = NULL;
	free_percpu(dev->lstats);
	free_netdev(dev);
}

/*
 * The loopback device is special. There is only one instance
 * per network namespace.
 */
static void snull_init(struct net_device *dev)
{
	dev->mtu		= 64 * 1024;
	dev->hard_header_len	= ETH_HLEN;	/* 14	*/
	dev->min_header_len	= ETH_HLEN;	/* 14	*/
	dev->addr_len		= ETH_ALEN;	/* 6	*/
	dev->type		= 0x0001;	/* 0x0001*/
	dev->flags		= IFF_LOOPBACK;
	dev->priv_flags		|= IFF_LIVE_ADDR_CHANGE | IFF_NO_QUEUE;
	netif_keep_dst(dev);
	dev->hw_features	= NETIF_F_ALL_TSO | NETIF_F_UFO;
	dev->features 		= NETIF_F_SG | NETIF_F_FRAGLIST
		| NETIF_F_ALL_TSO
		| NETIF_F_UFO
		| NETIF_F_HW_CSUM
		| NETIF_F_RXCSUM
		| NETIF_F_SCTP_CRC
		| NETIF_F_HIGHDMA
		| NETIF_F_LLTX
		| NETIF_F_NETNS_LOCAL
		| NETIF_F_VLAN_CHALLENGED
		| NETIF_F_LOOPBACK;
	//dev->ethtool_ops	= &loopback_ethtool_ops;
	//dev->header_ops		= &eth_header_ops;
	//dev->netdev_ops		= &loopback_ops;
	dev->destructor		= snull_dev_free;
}


static int kylo_create_eth_interface( void )
{
	int retval = -1;
	int size = (int)sizeof(struct snull_priv);


	/** alloc memory for new device */
	g_netdev = alloc_netdev( size, "sn%d", NET_NAME_UNKNOWN, snull_init );

	if( NULL == g_netdev ) {
		printk(KERN_CRIT "FAILED to alloc %d bytes\n", sizeof(size));
		return(-ENOMEM);
	}

	//if (!(g_netdev = alloc_etherdev(sizeof(struct priv_struct)))) {
	//	return -ENOMEM;
	//}

	printk(KERN_INFO "Allocated %d bytes\n", size);

	g_priv = netdev_priv(g_netdev);
#if 0
	retval = register_netdev(g_netdev);
	if(retval)
	{
		printk(KERN_WARNING "snull: error %i registering device \"%s\"\n",
			retval, g_netdev->name);
	}
	else {
		printk(KERN_INFO "Allocated %s device\n", g_netdev->name);
	}

	unregister_netdev(g_netdev);
#endif

	free_netdev(g_netdev);

	return(retval);
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


int kylo_create_proc_entry()
{
	g_len = 0; g_temp = 0;
	g_msg = NULL;

	proc_file_entry = proc_create(PROCFS_NAME, 0666, NULL, &proc_fops);
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


int kylo_remove_proc_entry()
{
	remove_proc_entry( PROCFS_NAME, NULL );

	if( g_msg == NULL ) {
	    return -ENOMEM;
	}

	kfree(g_msg);
	kfree(g_netdev);

	return(0);
}
