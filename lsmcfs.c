/*
===============================================================================
Driver Name		:		lsmcfs
Author			:		RAKSHIT-VAMSEE-RAIVITEJA
License			:		GPL
Description		:		LINUX DEVICE DRIVER PROJECT
===============================================================================
*/


#include "lsmc.h"
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/semaphore.h>

#define DRIVER_NAME "LSMFS"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("RAKSHIT-VAMSEE-RAVITEJA");

//GLOBAL DECLARATIONS////////////////////////////////////////////////////////////////////////////

#define SHA_DIGEST_LENGTH 20

int flag;
int DB_READY = 0;
int algo = 0;
char hashstring[41]={0};
struct semaphore sem;
struct proc_dir_entry *entry;
struct list_head appHead;
struct list_head fileHead;

struct lsmc_ds_node{
	char lsmc_obj_path[100];
	char lsmc_obj_hash[41];
	struct inode *inode;
	struct list_head lsmc_list;
};

//HELPER FUNCTIONS//////////////////////////////////////////////////////////////////////////////
/*
 * displaydb : Displays database contents.
 *
*/
void displaydb(void) {
	
	struct lsmc_ds_node *temp;

	list_for_each_entry(temp,&appHead,lsmc_list)
		printk(KERN_ALERT "app_list :%s",temp->lsmc_obj_path);

	temp = NULL;
	list_for_each_entry(temp,&fileHead,lsmc_list)
		printk(KERN_ALERT "file_list :%s : %lu",temp -> lsmc_obj_path, temp->inode->i_ino);
	
	printk(KERN_ALERT "displaydb ended\n");
}

/*
 * lsmc_calc_hash: calculates the hash of the path.
 *
*/


char *lsmc_calc_hash (char *path) {

	struct scatterlist sg;
	struct hash_desc desc;
	char hashtext[41]={0};
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
	hashstring[40] = '\0';
	return hashstring;
}

/*
 * lsmc_get_app_hash : This function searches for the hash value in the database. If the hash value is present in database 0 is returned    
 *   					else -1 is returned.
 *
 */
int lsmc_get_app_hash(char *app_path){

	if(DB_READY) {
		struct lsmc_ds_node *temp;
		list_for_each_entry(temp, &appHead, lsmc_list) {
			if (!strcmp(temp->lsmc_obj_path, app_path)) {
				if (!strcmp(temp->lsmc_obj_hash, lsmc_calc_hash(app_path))) 
					return 0;
				else break;
			}
		}
	}
	return -1;
}
EXPORT_SYMBOL_GPL(lsmc_get_app_hash);

/*
 * lsmc_get_file_hash : This function searches if the inode no is in the database. If the inode no is present in database 0 is returned    
 *   					else -1 is returned.
 *
 */
int lsmc_get_file_hash(struct inode* inode){

	if(DB_READY) {
		struct lsmc_ds_node *temp;
		list_for_each_entry(temp,&fileHead,lsmc_list){
			if(temp->inode->i_ino == inode->i_ino) {
				return 0;
			}
		}
	}
	return -1;
}
EXPORT_SYMBOL_GPL(lsmc_get_file_hash);

//FILE OPERATIONS FUNCTIONS/////////////////////////////////////////////////////////////////////////

ssize_t lsmc_proc_read(struct file *file, char *a, size_t size, loff_t *loff)
{
	down(&sem);
	copy_to_user(a,"ACK\0",4);

	return 0;
}

ssize_t lsmc_proc_write(struct file *file, const char *data, size_t count, loff_t *loff)
{
	struct lsmc_ds_node *temp;
	struct path path;
	char *userdata;

	userdata = kmalloc (count, GFP_KERNEL);
	copy_from_user(userdata,data,count);
	userdata[strlen(userdata)-1] = '\0';

	if(!strncmp (userdata, "FILE_END",8))
		flag = 1;
	else if(!strncmp (userdata, "APP_END",7)) {
		displaydb();
		DB_READY = 1;
		return 0;
	}

	else if(userdata != NULL) {
		if (flag == 0) {			
			temp = kmalloc (sizeof (struct lsmc_ds_node), GFP_KERNEL);			
			kern_path(userdata, LOOKUP_FOLLOW, &path);
			temp->inode = path.dentry->d_inode;
			strcpy (temp->lsmc_obj_path, userdata);						
			list_add(&temp->lsmc_list,&fileHead);				
		}
		else if(flag == 1) {
			temp = kmalloc (sizeof (struct lsmc_ds_node), GFP_KERNEL);
			strcpy (temp->lsmc_obj_path, userdata);
			strcpy (temp->lsmc_obj_hash, lsmc_calc_hash (userdata));
			list_add(&temp->lsmc_list,&appHead);
		}
	}

	kfree(userdata);
	up(&sem);
	return 0;
}

struct file_operations lsmc_file_ops = {
	    .owner = THIS_MODULE,
	    .read = lsmc_proc_read,
	    .write = lsmc_proc_write,
};

//////////////////////////////////////////////////////////////////////////////////////
/* Creating a node in procfs */

static int __init lsmcfs_init(void)
{
	entry = proc_create("lsmc", 0, NULL, &lsmc_file_ops);
	if (!entry) {
		printk(KERN_ALERT "lsmc proc node creation failed");
		return -ENOENT;
	}
	printk(KERN_ALERT "LSMC proc node created");

	flag = 0;
	sema_init(&sem,0);
	INIT_LIST_HEAD(&appHead);
	INIT_LIST_HEAD(&fileHead);

	return 0;
}

fs_initcall(lsmcfs_init);

