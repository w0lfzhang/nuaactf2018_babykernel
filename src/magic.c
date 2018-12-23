/*
* author: w0lfzhang
* date: 2018.12.20
* For NUAA CTF 2018, a simple char-dev driver for kernel pwn challenge.
* It means to teach the baby pwners to learn the kernel exploit
* technologies and let them start their trip to the kernel-pwn.
*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/uaccess.h> 
#include <linux/string.h>
#include <linux/device.h>

#define log(...) printk(KERN_INFO __VA_ARGS__)
//#define SECRET "w0lfzhang"
#define MAGIC_BUF_SIZE 0x30
#define FLAG_FILE "/root/flag"

static unsigned long canary;

static struct class *magic_class;

static int cat_flag(void) __attribute__ ((used));

static int cat_flag(void)
{
	char flag[MAGIC_BUF_SIZE];
	struct file *fp;
	mm_segment_t fs;
	loff_t pos;

	memset(flag, 0, MAGIC_BUF_SIZE);

	fp = filp_open(FLAG_FILE, O_RDONLY, 0);
	if ( IS_ERR(fp) ){
		log("Open flag failed!\n");
		return -1;
	}

	fs = get_fs();
	set_fs(KERNEL_DS);
	pos = 0;
	vfs_read(fp, flag, MAGIC_BUF_SIZE - 1, &pos);

	log("Here is the flag: %s\n", flag);
	filp_close(fp, NULL);
	set_fs(fs);

	return 0;
}

static int magic_dev_open(struct inode *inode, struct file *file)
{
	log("Magic device opened!");

	return 0;
}

static ssize_t magic_dev_read(struct file *filp, char __user *buf, size_t count, loff_t *off)
{
	int ret;
	char magic_buf[MAGIC_BUF_SIZE];
	memset(magic_buf, 0, MAGIC_BUF_SIZE);

	canary = ((unsigned long *)magic_buf)[6];
	ret = copy_to_user(buf, magic_buf, count);
	if( !ret ){
		log("Read from magic device successful!\n");
		
		return count;
	}
	else{
		return -1;
	}
}

static ssize_t magic_dev_write(struct file *filp, const char __user *buf, size_t count, loff_t *off)
{
	int ret;
	int (*magic_func)(void);
	char magic_buf[MAGIC_BUF_SIZE];
	memset(magic_buf, 0, MAGIC_BUF_SIZE);
	if( count < MAGIC_BUF_SIZE ){
		count = 0x38;
	}
	ret = copy_from_user(magic_buf, buf, count);
	if( ! ret ){
		log("Write to magic device successful!\n");
		if( canary == ((unsigned long *)magic_buf)[6] ){
			magic_func = ((unsigned long *)magic_buf)[0];
			log("magic_func addr: %p\n", magic_func);
			magic_func();
		}
		return count;
	}
	else{
		return -1;
	}
}

static struct file_operations magic_dev_ops = {
	.owner = THIS_MODULE,
	.open = magic_dev_open,
	.read = magic_dev_read,
	.write = magic_dev_write,
};

/* no error checking, just for simple*/
static int __init init_magic_dev(void)
{
	int ret;

	ret = register_chrdev(222, "magic", &magic_dev_ops);
	
	log("Magic deivce register!\n");

	magic_class = class_create(THIS_MODULE, "magic_class");
	
	device_create(magic_class, NULL, MKDEV(222, 0), NULL, "magic");

	return ret;
}

static void __exit exit_maigc_dev(void)
{
	unregister_chrdev(222, "magic");
	log("Magic device removed!\n");

	device_destroy(magic_class, MKDEV(222, 0));
	class_destroy(magic_class);
}

module_init(init_magic_dev);
module_exit(exit_maigc_dev);

MODULE_LICENSE("GPL");