#include <linux/module.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include "rule.c"
#include "log.c"

#define MYMAJOR	200
#define MYNAME	"wxk_cdev"

dev_t devid;
struct cdev cdev;
struct class * cls;
struct device * class_dev;

int cdev_open(struct inode *inode,struct file * file){
    printk(KERN_INFO "chardev open\n");
	return 0;
}
ssize_t cdev_read(struct file * file,char  __user *buf,size_t size,loff_t *ppos){
    //char a[10]="123"; 
    //copy_to_user(buf,a,10);
    int num = size/sizeof(Rule);
    if(rule_num<num){
        num= rule_num;
    }
    copy_to_user(buf,(char *)rules,num*sizeof(Rule));
    return num;
}

ssize_t cdev_write(struct file * file,const char __user * user,size_t size,loff_t *ppos){
    //char a[10];
    //copy_from_user(a,user,10);
    //printk("%s\n",a);
    Rule tmp;
    copy_from_user((char *)&tmp,user,sizeof(Rule));
    int action = tmp.action>>24;
    tmp.action = tmp.action &0xff;
    if(action == ADD_RULE){
        add_rule(&tmp);
    }else if(action == DEL_RULE){
        del_rule(&tmp);
    }
    return 0;
}
struct file_operations cdev_fops={
    .open = cdev_open,
    .read = cdev_read,
    .write = cdev_write,
};
