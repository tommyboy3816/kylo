/*
 * main.c
 *
 *  Created on: Jul 12, 2017
 *      Author: ralph
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include "proc.h"


char g_ver[128];

#ifdef KYLOVER
	int x = KYLOVER;
#else
	int x = 2;
#endif
static int __init kylo_init( void )
{
	int retval = 0;

	snprintf(g_ver, 128, "kylo%d", x);
	printk(KERN_INFO "Kylo Init %d {%s}\n", x, g_ver);

	/** Setup proc file */
	kylo_create_proc_entry();

	return(retval);
}


static void __exit kylo_exit( void )
{
	printk(KERN_INFO "Kylo Exit %d\n", x);

	snull_cleanup();

	kylo_remove_proc_entry();
}

module_init(kylo_init);
module_exit(kylo_exit);

MODULE_AUTHOR("Kylo Ren");
MODULE_DESCRIPTION("I hate crybabies");
MODULE_LICENSE("GPL");
