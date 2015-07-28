/*
===============================================================================
Driver Name		:		LSMC
Author			:		RAKSHIT-VAMSEE-RAVITEJA
License			:		GPL
Description		:		LINUX DEVICE DRIVER PROJECT
===============================================================================
*/


//INCLUDES/////////////////////////////////////////////////////////////////////

#include "lsmc.h"
#include "lsmcfs.h"


//DEFINES//////////////////////////////////////////////////////////////////////
#define DRIVER_NAME "LSM_module"
#define MODULE_NAME "lsm"

//ABOUT////////////////////////////////////////////////////////////////////////


MODULE_AUTHOR("RAKSHIT-VAMSEE-RAVITEJA");
MODULE_DESCRIPTION("Simple Linux Security Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.1");

//GLOBALS//////////////////////////////////////////////////////////////////////

extern struct security_operations *security_ops;


//HOOKS/////////////////////////////////////////////////////////////////////////

/*
 * lsm_file_permission : This hook is called when there is a read / write operation being done on the file.
 *
*/
static  int lsm_file_permission(struct file *file, int mask)
{
	char pathname[100],*p = NULL;
	int dbres = 0;
	struct inode *inode;
	struct lsmc_inode_sec *i_sec;


	inode = file->f_inode;
	i_sec = (struct lsmc_inode_sec *)inode->i_security;

	/* checking if file has to be protected. */
	if (i_sec->IS_SECURED || !(lsmc_get_file_hash (inode))) {

		i_sec->IS_SECURED = 1;

		/* file is found in the database. Hence should be protected. Finding executing app path */		
		if (current->mm) {
		    down_read(&current->mm->mmap_sem);
		    if (current->mm->exe_file) {
		    		memset(pathname,'\0',100);
		    		p = NULL;
					p = d_path(&current->mm->exe_file->f_path, pathname, 100);
				    /*Now you have the path name of exe in p*/
		    }
		    up_read(&current->mm->mmap_sem);
		} else return -EACCES;
		
		/* checking if app is whitelisted */
		dbres = lsmc_get_app_hash (p);
		if(dbres) {
			printk(KERN_ALERT "app not in database :%s",current->comm);
			return -EACCES;
		}
	}
	return 0;
}

/*
 * lsm_inode_alloc_security : allocates a security structure to each inode->i_security.
 *
*/
static int lsm_inode_alloc_security(struct inode *inode) {

	struct lsmc_inode_sec *i_sec;
	i_sec = kzalloc(sizeof(struct lsmc_inode_sec), GFP_KERNEL);
	if (!i_sec)
		return -ENOMEM;
	
	i_sec->inode = inode;
	i_sec->IS_SECURED = 0;
	memset(i_sec->path,'\0',100);
	inode->i_security = i_sec;
	return 0;
}

/*
 * lsm_inode_free_security : deallocates security structure from inode->i_security.
 *
*/
static void lsm_inode_free_security(struct inode *inode) {

	struct lsmc_inode_sec *i_sec ;
	i_sec = inode->i_security ;
	if(i_sec)
		kzfree(i_sec);
	inode->i_security = NULL;
}


//STRUCTS//////////////////////////////////////////////////////////////////////
static struct security_operations lsm_ops = {
		.name							=				"LSM",
		.file_permission				=				lsm_file_permission,
		.inode_alloc_security			=				lsm_inode_alloc_security,
		.inode_free_security			=				lsm_inode_free_security,
};


//INIT/////////////////////////////////////////////////////////////////////////
static __init int LSM_module_init(void)
{

    if (register_security(&lsm_ops)) {
    	printk(KERN_ALERT "lsmc failed");
        panic(KERN_INFO "Failed to register LSM module\n");
    }
    printk(KERN_ALERT "lsmc started");

    return 0;

}
security_initcall(LSM_module_init);

