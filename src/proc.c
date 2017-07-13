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
#include <asm-generic/uaccess.h>	/* for copy_from_user */
#include "proc.h"


static struct proc_dir_entry *proc_file_entry;
static char *g_msg = NULL;
static int g_temp = 0, g_len = 0;


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

/**
 * @fn
 * @brief
 * @param filp
 * @param buf
 * @param count
 * @param offp
 * @return
 */
static int kylo_write_proc_callback(struct file *filp, const char *buf, size_t count, loff_t *offp)
{
	printk(KERN_INFO "%s: count %d\n", __FUNCTION__, count);

	strncpy(g_msg, buf, MSGSIZE);
	g_len = count;
	g_temp = g_len;

	return count;
}


int kylo_read_proc_callback( struct file *filp, char *buf, size_t count, loff_t *offp )
{
	static int finished = 0;
	int ret = MSGSIZE;

	printk(KERN_INFO "/proc/%s count %d, finished %d\n", PROCFS_NAME, count, finished);

	if( finished ) {
		printk(KERN_INFO "procfs_read: END {count %d}\n", count);
		finished = 0;
		return 0;
	}

	finished = 1;
	ret = strlen(g_msg);
	strncpy(buf, g_msg, MSGSIZE);

	return(ret);
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

	return(0);
}
