/*
 * proc.h
 *
 *  Created on: Jul 13, 2017
 *      Author: ralph
 */

#ifndef HDR_PROC_H_
#define HDR_PROC_H_


#define PROCFS_MAX_SIZE     1024
#define PROCFS_NAME         "kylo"
#define MSGSIZE             250

int kylo_create_proc_entry( void );
int kylo_remove_proc_entry( void );


#endif /* HDR_PROC_H_ */
