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

static int __init kylo_init( void )
{
	int retval = 0;


	printk(KERN_INFO "Kylo Init\n");

	/** Setup proc file */
	kylo_create_proc_entry();

	return(retval);
}


static void __exit kylo_exit( void )
{
	printk(KERN_INFO "Kylo Exit\n");
	kylo_remove_proc_entry();
}

module_init(kylo_init);
module_exit(kylo_exit);

MODULE_AUTHOR("Kylo Ren");
MODULE_DESCRIPTION("I hate crybabies");
MODULE_LICENSE("GPL");
