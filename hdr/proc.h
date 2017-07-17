/*
 * proc.h
 *
 *  Created on: Jul 13, 2017
 *      Author: ralph
 */

#ifndef HDR_PROC_H_
#define HDR_PROC_H_

#include <linux/netdevice.h> /* struct device, and other headers */


extern char g_ver[];

#define PROCFS_MAX_SIZE     1024
//#define PROCFS_NAME         "kylo1"
#define MSGSIZE             250
#define MAX_SNULLS          2


/* These are the flags in the statusword */
#define SNULL_RX_INTR 0x0001
#define SNULL_TX_INTR 0x0002

/* Default timeout period */
#define SNULL_TIMEOUT 5   /* In jiffies */

#define  SNULL_DYNAMIC  1
#ifdef SNULL_DYNAMIC
extern struct net_device **snull_devs;
extern u_int32_t g_snull_idx;
#else
extern struct net_device *snull_devs[];
#endif

/*
 * Macros to help debugging
 */

#undef PDEBUG             /* undef it, just in case */
#ifdef SNULL_DEBUG
#  ifdef __KERNEL__
     /* This one if debugging is on, and kernel space */
#    define PDEBUG(fmt, args...) printk( KERN_DEBUG "snull: " fmt, ## args)
#  else
     /* This one for user space */
#    define PDEBUG(fmt, args...) fprintf(stderr, fmt, ## args)
#  endif
#else
#  define PDEBUG(fmt, args...) /* not debugging: nothing */
#endif

#undef PDEBUGG
#define PDEBUGG(fmt, args...) /* nothing: it's a placeholder */

/*
 * This structure is private to each device. It is used to pass
 * packets in and out, so there is place for a packet
 */

struct snull_priv {
	struct net_device_stats stats;
	int status;
	struct snull_packet *ppool;
	struct snull_packet *rx_queue;  /* List of incoming packets */
	int rx_int_enabled;
	int tx_packetlen;
	u_int8_t *tx_packetdata;
	struct sk_buff *skb;
	spinlock_t lock;
	struct net_device *dev;
	struct napi_struct napi;
};


/*
 * A structure representing an in-flight packet.
 */
struct snull_packet {
	struct snull_packet *next;
	struct net_device *dev;
	int	datalen;
	u_int8_t data[ETH_DATA_LEN];
};


static void snull_tx_timeout(struct net_device *dev);
static void (*snull_interrupt)(int, void *, struct pt_regs *);

void snull_cleanup(void);
int kylo_create_proc_entry( void );
int kylo_remove_proc_entry( void );


#endif /* HDR_PROC_H_ */
