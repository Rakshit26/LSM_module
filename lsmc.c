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


//DEFINES//////////////////////////////////////////////////////////////////////

#define MODULE_NAME "lsm"
static int vendor_id = 0x0781;
static int product_id = 0x5583;

//ABOUT////////////////////////////////////////////////////////////////////////


MODULE_AUTHOR("RAKSHIT-VAMSEE-RAVITEJA");
MODULE_DESCRIPTION("Simple Linux Security Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1.1");


//GLOBALS//////////////////////////////////////////////////////////////////////

extern struct security_operations *security_ops;

//HELPER_FUNCTIONS/////////////////////////////////////////////////////////////

static int match_device(struct usb_device* dev)
{
	struct usb_device* dev_child;
    int retval = -ENODEV;
    int child;

    if ((dev->descriptor.idVendor == vendor_id) &&
        (dev->descriptor.idProduct == product_id))
    {
        return 0;
    }

    for (child = 0; child < dev->maxchild; ++child)
    {
    	if ((dev_child = usb_hub_find_child(dev,child)) != NULL ) {

    		retval = match_device(dev_child);
			if (retval == 0)
				return retval;
    	}
    }

    return retval;
}


static int find_usb_device(void)
{
    struct list_head* buslist;
    struct usb_bus* bus;
    int retval = -ENODEV;

    mutex_lock(&usb_bus_list_lock);

    for (buslist = usb_bus_list.next; buslist != &usb_bus_list; buslist = buslist->next)
    {
        bus = container_of(buslist, struct usb_bus, bus_list);
        retval = match_device(bus->root_hub);
        if (retval == 0)
        {
            break;
        }
    }

    mutex_unlock(&usb_bus_list_lock);
    return retval;
}



//HOOKS/////////////////////////////////////////////////////////////////////////


static  int lsm_ptrace_access_check(struct task_struct *child,
					     unsigned int mode)
{
	return 0;
}

static  int lsm_ptrace_traceme(struct task_struct *parent)
{
	return 0;
}

static  int lsm_capget(struct task_struct *target,
				   kernel_cap_t *effective,
				   kernel_cap_t *inheritable,
				   kernel_cap_t *permitted)
{
	return 0;
}

static  int lsm_capset(struct cred *new,
				   const struct cred *old,
				   const kernel_cap_t *effective,
				   const kernel_cap_t *inheritable,
				   const kernel_cap_t *permitted)
{
	return 0;
}

static  int lsm_capable(const struct cred *cred,
				   struct user_namespace *ns, int cap)
{
	return 0;
}



static  int lsm_quotactl(int cmds, int type, int id,
				     struct super_block *sb)
{
	return 0;
}

static  int lsm_quota_on(struct dentry *dentry)
{
	return 0;
}

static  int lsm_syslog(int type)
{
	return 0;
}

static  int lsm_settime(const struct timespec *ts,
				   const struct timezone *tz)
{
	return 0;
}


static int lsm_bprm_check_security (struct linux_binprm *bprm){
	return 0;
}

static  int lsm_bprm_set_creds(struct linux_binprm *bprm)
{
	return 0;
}

static  int lsm_bprm_check(struct linux_binprm *bprm)
{
	return 0;
}

static  void lsm_bprm_committing_creds(struct linux_binprm *bprm)
{
}

static  void lsm_bprm_committed_creds(struct linux_binprm *bprm)
{
}

static  int lsm_bprm_secureexec(struct linux_binprm *bprm)
{
	return 0;
}

static  int lsm_sb_alloc_security(struct super_block *sb)
{
	return 0;
}

static  void lsm_sb_free_security(struct super_block *sb)
{ }

static  int lsm_sb_copy_data(char *orig, char *copy)
{
	return 0;
}

static  int lsm_sb_remount(struct super_block *sb, void *data)
{
	return 0;
}

static  int lsm_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
	return 0;
}

static  int lsm_sb_show_options(struct seq_file *m,
					   struct super_block *sb)
{
	return 0;
}

static  int lsm_sb_statfs(struct dentry *dentry)
{
	return 0;
}

static  int lsm_sb_mount(const char *dev_name, struct path *path,
				    const char *type, unsigned long flags,
				    void *data)
{
	return 0;
}

static  int lsm_sb_umount(struct vfsmount *mnt, int flags)
{
	return 0;
}

static  int lsm_sb_pivotroot(struct path *old_path,
					struct path *new_path)
{
	return 0;
}

static  int lsm_sb_set_mnt_opts(struct super_block *sb,
					   struct security_mnt_opts *opts,
					   unsigned long kern_flags,
					   unsigned long *set_kern_flags)
{
	return 0;
}

static  int lsm_sb_clone_mnt_opts(const struct super_block *oldsb,
					      struct super_block *newsb)
{
	return 0;
}

static  int lsm_sb_parse_opts_str(char *options, struct security_mnt_opts *opts)
{
	return 0;
}

static  int lsm_inode_alloc_security(struct inode *inode)
{
	return 0;
}

static  void lsm_inode_free_security(struct inode *inode)
{ }

static  int lsm_dentry_init_security(struct dentry *dentry,
						 int mode,
						 struct qstr *name,
						 void **ctx,
						 u32 *ctxlen)
{
	return 0;
}


static  int lsm_inode_init_security(struct inode *inode, struct inode *dir,
									const struct qstr *qstr, const char **name,
									void **value, size_t *len)
{
	return 0;
}

static  int lsm_old_inode_init_security(struct inode *inode,
						   struct inode *dir,
						   const struct qstr *qstr,
						   const char **name,
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

static  int lsm_inode_link(struct dentry *old_dentry,
				       struct inode *dir,
				       struct dentry *new_dentry)
{
	return 0;
}

static  int lsm_inode_unlink(struct inode *dir,
					 struct dentry *dentry)
{
	return 0;
}

static  int lsm_inode_symlink(struct inode *dir,
					  struct dentry *dentry,
					  const char *old_name)
{
	return 0;
}

static  int lsm_inode_mkdir(struct inode *dir,
					struct dentry *dentry,
					int mode)
{
	return 0;
}

static  int lsm_inode_rmdir(struct inode *dir,
					struct dentry *dentry)
{
	return 0;
}

static  int lsm_inode_mknod(struct inode *dir,
					struct dentry *dentry,
					int mode, dev_t dev)
{
	return 0;
}

static  int lsm_inode_rename(struct inode *old_dir,
					 struct dentry *old_dentry,
					 struct inode *new_dir,
					 struct dentry *new_dentry,
					 unsigned int flags)
{
	return 0;
}

static  int lsm_inode_readlink(struct dentry *dentry)
{
	return 0;
}

static  int lsm_inode_follow_link(struct dentry *dentry,
					      struct nameidata *nd)
{
	return 0;
}

static  int lsm_inode_permission(struct inode *inode, int mask)
{
	if (find_usb_device() != 0)
	    {
	        printk(KERN_ALERT "You shall not pass!\n");
	        return -EACCES;
	    }
	    else {
	        printk(KERN_ALERT "Found supreme USB device\n");
	    }

	    return 0;
}

static  int lsm_inode_setattr(struct dentry *dentry,
					  struct iattr *attr)
{
	return 0;
}

static  int lsm_inode_getattr(const struct path *path)
{
	return 0;
}

static  int lsm_inode_setxattr(struct dentry *dentry,
		const char *name, const void *value, size_t size, int flags)
{
	return 0;
}

static  void lsm_inode_post_setxattr(struct dentry *dentry,
		const char *name, const void *value, size_t size, int flags)
{ }

static  int lsm_inode_getxattr(struct dentry *dentry,
			const char *name)
{
	return 0;
}

static  int lsm_inode_listxattr(struct dentry *dentry)
{
	return 0;
}

static  int lsm_inode_removexattr(struct dentry *dentry,
			const char *name)
{
	return 0;
}

static  int lsm_inode_need_killpriv(struct dentry *dentry)
{
	return 0;
}

static  int lsm_inode_killpriv(struct dentry *dentry)
{
	return 0;
}

static  int lsm_inode_getsecurity(const struct inode *inode, const char *name, void **buffer, bool alloc)
{
	return 0;
}

static  int lsm_inode_setsecurity(struct inode *inode, const char *name, const void *value, size_t size, int flags)
{
	return 0;
}

static  int lsm_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size)
{
	return 0;
}

static  void lsm_inode_getsecid(const struct inode *inode, u32 *secid)
{
	*secid = 0;
}

static  int lsm_file_permission(struct file *file, int mask)
{
	if (find_usb_device() != 0)
	    {
	        printk(KERN_ALERT "You shall not pass!\n");
	        return -EACCES;
	    }
	    else {
	        printk(KERN_ALERT "Found supreme USB device\n");
	    }

	    return 0;
}

static  int lsm_file_alloc_security(struct file *file)
{
	return 0;
}

static  void lsm_file_free_security(struct file *file)
{ }

static  int lsm_file_ioctl(struct file *file, unsigned int cmd,
				      unsigned long arg)
{
	return 0;
}

static  int lsm_mmap_file(struct file *file, unsigned long prot,
				     unsigned long flags)
{
	return 0;
}

static  int lsm_mmap_addr(unsigned long addr)
{
	return 0;
}

static  int lsm_file_mprotect(struct vm_area_struct *vma,
					 unsigned long reqprot,
					 unsigned long prot)
{
	return 0;
}

static  int lsm_file_lock(struct file *file, unsigned int cmd)
{
	return 0;
}

static  int lsm_file_fcntl(struct file *file, unsigned int cmd,
				      unsigned long arg)
{
	return 0;
}

static  void lsm_file_set_fowner(struct file *file)
{
	return;
}

static  int lsm_file_send_sigiotask(struct task_struct *tsk,
					       struct fown_struct *fown,
					       int sig)
{
	return 0;
}

static  int lsm_file_receive(struct file *file)
{
	return 0;
}

static  int lsm_file_open(struct file *file,
				     const struct cred *cred)
{
	return 0;
}

static  int lsm_task_create(unsigned long clone_flags)
{
	return 0;
}

static  void lsm_task_free(struct task_struct *task)
{ }

static  int lsm_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	return 0;
}

static  void lsm_cred_free(struct cred *cred)
{ }

static  int lsm_prepare_creds(struct cred *new,
					 const struct cred *old,
					 gfp_t gfp)
{
	return 0;
}

static  void lsm_transfer_creds(struct cred *new,
					   const struct cred *old)
{
}

static int lsm_cred_prepare (struct cred *new, const struct cred *old,
		    gfp_t gfp) {
	return 0;
}

static void lsm_cred_transfer(struct cred *new, const struct cred *old) {

}

static  int lsm_kernel_act_as(struct cred *cred, u32 secid)
{
	return 0;
}

static  int lsm_kernel_create_files_as(struct cred *cred,
						  struct inode *inode)
{
	return 0;
}

static  int lsm_kernel_fw_from_file(struct file *file,
					       char *buf, size_t size)
{
	return 0;
}

static  int lsm_kernel_module_request(char *kmod_name)
{
	return 0;
}

static  int lsm_kernel_module_from_file(struct file *file)
{
	return 0;
}

static  int lsm_task_fix_setuid(struct cred *new,
					   const struct cred *old,
					   int flags)
{
	return 0;
}

static  int lsm_task_setpgid(struct task_struct *p, pid_t pgid)
{
	return 0;
}

static  int lsm_task_getpgid(struct task_struct *p)
{
	return 0;
}

static  int lsm_task_getsid(struct task_struct *p)
{
	return 0;
}

static  void lsm_task_getsecid(struct task_struct *p, u32 *secid)
{
	*secid = 0;
}

static  int lsm_task_setnice(struct task_struct *p, int nice)
{
	return 0;
}

static  int lsm_task_setioprio(struct task_struct *p, int ioprio)
{
	return 0;
}

static  int lsm_task_getioprio(struct task_struct *p)
{
	return 0;
}

static  int lsm_task_setrlimit(struct task_struct *p,
					  unsigned int resource,
					  struct rlimit *new_rlim)
{
	return 0;
}

static  int lsm_task_setscheduler(struct task_struct *p)
{
	return 0;
}

static  int lsm_task_getscheduler(struct task_struct *p)
{
	return 0;
}

static  int lsm_task_movememory(struct task_struct *p)
{
	return 0;
}

static  int lsm_task_kill(struct task_struct *p,
				     struct siginfo *info, int sig,
				     u32 secid)
{
	return 0;
}

static  int lsm_task_wait(struct task_struct *p)
{
	return 0;
}

static  int lsm_task_prctl(int option, unsigned long arg2,
				      unsigned long arg3,
				      unsigned long arg4,
				      unsigned long arg5)
{
	return 0;
}

static  void lsm_task_to_inode(struct task_struct *p, struct inode *inode)
{ }

//STRUCTS//////////////////////////////////////////////////////////////////////
static struct security_operations lsm_ops = {
		.name							=				"lsm",

		.ptrace_access_check			=				lsm_ptrace_access_check,

		.ptrace_traceme					=				lsm_ptrace_traceme,
		.capget							=				lsm_capget,
		.capset							=				lsm_capset,
//		.capable						=				lsm_capable,
		.quotactl						=				lsm_quotactl,
		.quota_on						=				lsm_quota_on,
		.syslog							=				lsm_syslog,
		.settime						=				lsm_settime,

		.bprm_set_creds					=				lsm_bprm_set_creds,
		.bprm_check_security			=				lsm_bprm_check_security,
		.bprm_secureexec				=				lsm_bprm_secureexec,
		.bprm_committing_creds			=				lsm_bprm_committing_creds,
		.bprm_committed_creds			=				lsm_bprm_committed_creds,

		.sb_alloc_security				=				lsm_sb_alloc_security,
		.sb_free_security				=				lsm_sb_free_security,
		.sb_copy_data					=				lsm_sb_copy_data,
		.sb_remount						=				lsm_sb_remount,
		.sb_kern_mount					=				lsm_sb_kern_mount,
		.sb_show_options				=				lsm_sb_show_options,
		.sb_statfs						=				lsm_sb_statfs,
		.sb_mount						=				lsm_sb_mount,
		.sb_umount						=				lsm_sb_umount,
		.sb_pivotroot					=				lsm_sb_pivotroot,
		.sb_set_mnt_opts				=				lsm_sb_set_mnt_opts,
		.sb_clone_mnt_opts				=				lsm_sb_clone_mnt_opts,
		.sb_parse_opts_str				=				lsm_sb_parse_opts_str,
		.dentry_init_security			=				lsm_dentry_init_security,


		.inode_alloc_security			=				lsm_inode_alloc_security,
		.inode_free_security			=				lsm_inode_free_security,
		.inode_init_security			=				lsm_inode_init_security,
		.inode_create					=				lsm_inode_create,
		.inode_link						=				lsm_inode_link,
		.inode_unlink					=				lsm_inode_unlink,
		.inode_symlink					=				lsm_inode_symlink,
//		.inode_mkdir					=				lsm_inode_mkdir,
		.inode_rmdir					=				lsm_inode_rmdir,
//		.inode_mknod					=				lsm_inode_mknod,
//		.inode_rename					=				lsm_inode_rename,
		.inode_readlink					=				lsm_inode_readlink,
		.inode_follow_link				=				lsm_inode_follow_link,
		.inode_permission				=				lsm_inode_permission,
		.inode_setattr					=				lsm_inode_setattr,
//		.inode_getattr					=				lsm_inode_getattr,
		.inode_setxattr					=				lsm_inode_setxattr,
		.inode_post_setxattr			=				lsm_inode_post_setxattr,
		.inode_getxattr					=				lsm_inode_getxattr,
		.inode_listxattr				=				lsm_inode_listxattr,
		.inode_removexattr				=				lsm_inode_removexattr,
		.inode_need_killpriv			=				lsm_inode_need_killpriv,
		.inode_killpriv					=				lsm_inode_killpriv,
		.inode_getsecurity				=				lsm_inode_getsecurity,
		.inode_setsecurity				=				lsm_inode_setsecurity,
		.inode_listsecurity				=				lsm_inode_listsecurity,
		.inode_getsecid					=				lsm_inode_getsecid,

		.file_permission				=				lsm_file_permission,
		.file_alloc_security			=				lsm_file_alloc_security,
		.file_free_security				=				lsm_file_free_security,
		.file_ioctl						=				lsm_file_ioctl,
		.mmap_addr						=				lsm_mmap_addr,
//		.mmap_file						=				lsm_mmap_file,
		.file_mprotect					=				lsm_file_mprotect,
		.file_lock						=				lsm_file_lock,
		.file_fcntl						=				lsm_file_fcntl,
		.file_set_fowner				=				lsm_file_set_fowner,
		.file_send_sigiotask			=				lsm_file_send_sigiotask,
		.file_receive					=				lsm_file_receive,
		.file_open						=				lsm_file_open,

		.task_create					=				lsm_task_create,
		.task_free						=				lsm_task_free,
		.cred_alloc_blank				=				lsm_cred_alloc_blank,
		.cred_free						=				lsm_cred_free,
		.cred_prepare					=				lsm_cred_prepare,
		.cred_transfer					=				lsm_cred_transfer,
		.kernel_act_as					=				lsm_kernel_act_as,
		.kernel_create_files_as			=				lsm_kernel_create_files_as,
		.kernel_fw_from_file			=				lsm_kernel_fw_from_file,
		.kernel_module_request			=				lsm_kernel_module_request,
		.kernel_module_from_file		=				lsm_kernel_module_from_file,
		.task_fix_setuid				=				lsm_task_fix_setuid,
		.task_setpgid					=				lsm_task_setpgid,
		.task_getpgid					=				lsm_task_getpgid,
		.task_getsid					=				lsm_task_getsid,
		.task_getsecid					=				lsm_task_getsecid,
		.task_setnice					=				lsm_task_setnice,
		.task_setioprio					=				lsm_task_setioprio,
		.task_getioprio					=				lsm_task_getioprio,
		.task_setrlimit					=				lsm_task_setrlimit,
		.task_setscheduler				=				lsm_task_setscheduler,
		.task_getscheduler				=				lsm_task_getscheduler,
		.task_movememory				=				lsm_task_movememory,
		.task_kill						=				lsm_task_kill,

		.task_wait						=				lsm_task_wait,
		.task_prctl						=				lsm_task_prctl,
		.task_to_inode					=				lsm_task_to_inode,
};

//INIT/////////////////////////////////////////////////////////////////////////

static int __init LSM_module_init(void)
{

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

