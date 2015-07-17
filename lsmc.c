/*
===============================================================================
Driver Name		:		LSM_module
Author			:		RAKSHIT-VAMSEE-RAVITEJA
License			:		GPL
Description		:		LINUX DEVICE DRIVER PROJECT
===============================================================================
*/

//INCLUDES/////////////////////////////////////////////////////////////////////

#include "lsmc.h"
//#include "scatterlist.h"
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
#include <linux/mm_types.h>
#include <linux/crypto.h>
#include <linux/cryptohash.h>
#include <linux/cryptouser.h>
#include <linux/scatterlist.h>


//DEFINES//////////////////////////////////////////////////////////////////////

#define MODULE_NAME "lsm"
#define SHA_DIGEST_LENGTH 20

static int INIT_STARTED = 0;

//ABOUT////////////////////////////////////////////////////////////////////////


MODULE_AUTHOR("RAKSHIT-VAMSEE-RAVITEJA");
MODULE_DESCRIPTION("Simple Linux Security Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1.1");


//GLOBALS//////////////////////////////////////////////////////////////////////

extern struct security_operations *security_ops;

//HELPER_FUNCTIONS/////////////////////////////////////////////////////////////

void hash_calc (char *path,char *hashstring) {

	struct scatterlist sg;
	struct hash_desc desc;
	char hashtext[41];
	int i;
	size_t len = strlen(path);


	sg_init_one(&sg, path, len);
	desc.tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);

/*  crypto_hash_init configures the hashing engine according to the supplied struct hash_desc.*/
	crypto_hash_init(&desc);

/*	crypto_hash_update performs the actual hashing method on the plaintext.*/
	crypto_hash_update(&desc, &sg, len);

/*	Finally, crypto_hash_final copies the hash to a character array.*/
	crypto_hash_final(&desc, hashtext);

	crypto_free_hash(desc.tfm);

	for ( i=0 ; i<SHA_DIGEST_LENGTH; i++ )
		sprintf(&(hashstring[i*2]),"%02x",hashtext[i]);
	return ;
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

	char *pathname,*p,*hashstring,*whitelist;
	int i = 0;

	if(INIT_STARTED) {
		if(!strcmp(current->comm,"gedit")){


			p = pathname = hashstring = NULL;

			/* Generating the path of the task */
	
			if (current->mm) {
			    down_read(&current->mm->mmap_sem);
			    if (current->mm->exe_file) {
					pathname = kmalloc(PATH_MAX, GFP_ATOMIC);

					if (pathname) {
						i=1;
						p = d_path(&current->mm->exe_file->f_path, pathname, PATH_MAX);
					    /*Now you have the path name of exe in p*/
					}
			   }
			   up_read(&current->mm->mmap_sem);
			}

			/*Compare the hash of the path */

			hashstring = kmalloc(41,GFP_ATOMIC);
			whitelist = kmalloc(41,GFP_ATOMIC);
			if(hashstring && whitelist) {
					hash_calc(p,hashstring);
					hash_calc("/usr/bin/gedit",whitelist);

					printk(KERN_ALERT " hash text-> %s\n",hashstring);
					printk(KERN_ALERT "PATH pointer-> %s\n",p);
					if (!strcmp(hashstring,whitelist)) {
					    	printk(KERN_ALERT "You shall not pass!\n");
						if(i)
							kfree(pathname);
						kfree(hashstring);
						kfree(whitelist);
						return -EACCES;
				    }
				   	kfree(hashstring);
					kfree(whitelist);				
				}

				if(i)
					kfree(pathname);
		}
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

static int lsm_task_create (unsigned long clone_flags) {
	
	if (!strcmp(current->comm,"init")) {
		INIT_STARTED = 1;
	}
	
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
		.task_create				=				lsm_task_create,

};


//INIT/////////////////////////////////////////////////////////////////////////

static __init int LSM_module_init(void)
{
/*

	if (!security_module_enable(&lsm_ops)) {
		printk(KERN_INFO "LSMC:  Disabled at boot.\n");
		return 0;
	}
*/

    if (register_security(&lsm_ops))
    {
    	printk(KERN_ALERT "lsm failed");
        panic(KERN_INFO "Failed to register LSM module\n");
    }

    printk(KERN_ALERT "lsm started");

    return 0;

}

security_initcall(LSM_module_init);

