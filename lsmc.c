/*
===============================================================================
Driver Name		:		LSM_module
Author			:		RAKSHIT-VAMSEE-RAVITEJA
License			:		GPL
Description		:		LINUX DEVICE DRIVER PROJECT
===============================================================================
*/

//INCLUDES/////////////////////////////////////////////////////////////////////

#include"lsmc.h"
#include <linux/init.h>
#include <linux/kd.h>
#include <linux/kernel.h>
#include <linux/tracehook.h>
#include <linux/errno.h>
#include <linux/ext2_fs.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/tty.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/net_namespace.h>
#include <net/netlabel.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <asm/atomic.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/dccp.h>
#include <linux/quota.h>
#include <linux/un.h>
#include <net/af_unix.h>
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <net/ipv6.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/audit.h>
#include <linux/string.h>
#include <linux/selinux.h>
#include <linux/mutex.h>
#include <linux/posix-timers.h>
#include <linux/syslog.h>
#include <linux/user_namespace.h>
#include <linux/usb.h>
#include <linux/usb/hcd.h>
#include <linux/cred.h>


//DEFINES//////////////////////////////////////////////////////////////////////

#define MODULE_NAME "lsm"
static int count_max = 0 ;

//ABOUT////////////////////////////////////////////////////////////////////////


MODULE_AUTHOR("RAKSHIT-VAMSEE-RAVITEJA");
MODULE_DESCRIPTION("Simple Linux Security Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1.1");


//GLOBALS//////////////////////////////////////////////////////////////////////

extern struct security_operations *security_ops;

//HELPER_FUNCTIONS/////////////////////////////////////////////////////////////

static int find_current_task(struct task_struct *ctask)
{
    int retval = -EACCES;

    if (!strcmp (ctask->parent->comm,"init")) {
    	if (!strcmp (ctask->comm,"gedit"))
    	    		return -EACCES;
    	    	else
    	    		return 0;
    }

/*check is any of the parent process is gedit .. loop till init process */
 
    while (strcmp (ctask->parent->comm,"init")) {

    	if (!strcmp (ctask->comm,"gedit"))
    		return -EACCES;
    	else {
    		retval = find_current_task (ctask->parent);
	}
    }

    return retval;
}


//HOOKS/////////////////////////////////////////////////////////////////////////


static int lsm_bprm_check_security (struct linux_binprm *bprm){
	return 0;
}

//inode hooks/////////////////////////////////////////////////////////////////

static  int lsm_inode_alloc_security(struct inode *inode)
{
	return 0;
}

static  void lsm_inode_free_security(struct inode *inode)
{ }


static  int lsm_inode_init_security(struct inode *inode, struct inode *dir,
									const struct qstr *qstr, const char **name,
									void **value, size_t *len)
{
	return 0;
}

static  int	lsm_inode_create(struct inode *dir,
					 struct dentry *dentry,
					 umode_t mode)
{
	return 0;
}

static  int lsm_inode_permission(struct inode *inode, int mask)
{
	return 0;
}


//file hooks/////////////////////////////////////////////////////////////////

/* This hook is called when there is a read / write operation being done on the file */

static  int lsm_file_permission(struct file *file, int mask)
{
	if (find_current_task(current) != 0)
	    {
	        printk(KERN_ALERT "You shall not pass!\n");
	        return -EACCES;
	    }
	    else {
	        printk(KERN_ALERT "You can pass for now !\n");
	    }

	    return 0;
}

static  int lsm_file_alloc_security(struct file *file)
{
	return 0;
}

static  void lsm_file_free_security(struct file *file)
{ }

static  int lsm_file_open(struct file *file,
				     const struct cred *cred)
{
	return 0;
}


//STRUCTS//////////////////////////////////////////////////////////////////////
static struct security_operations lsm_ops = {
		.name							=				"LSM",

		.bprm_check_security			=				lsm_bprm_check_security,

		.inode_alloc_security			=				lsm_inode_alloc_security,
		.inode_free_security			=				lsm_inode_free_security,
		.inode_init_security			=				lsm_inode_init_security,
		.inode_create					=				lsm_inode_create,
		.inode_permission				=				lsm_inode_permission,


		.file_permission				=				lsm_file_permission,
		.file_alloc_security			=				lsm_file_alloc_security,
		.file_free_security				=				lsm_file_free_security,
		.file_open						=				lsm_file_open,

};

//INIT/////////////////////////////////////////////////////////////////////////

static int __init LSM_module_init(void)
{

	if (!security_module_enable(&lsm_ops)) {
		printk(KERN_INFO "LSMC:  Disabled at boot.\n");
		return 0;
	}


    if (register_security(&lsm_ops))
    {
    	printk(KERN_ALERT "lsm failed");
        panic(KERN_INFO "Failed to register LSM module\n");
    }

    printk(KERN_ALERT "lsm started");

    return 0;

}

static void __exit LSM_module_exit(void)
{

	PINFO("EXIT\n");
}


module_init(LSM_module_init);
module_exit(LSM_module_exit);

