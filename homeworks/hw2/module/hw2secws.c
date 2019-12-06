
#undef __KERNEL__
#define __KERNEL__
#undef MODULE
#define MODULE

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Reuven Plevinsky");

static struct nf_hook_ops *nfho = NULL;
static struct nf_hook_ops *nfho1 = NULL;
static struct nf_hook_ops *nfho2 = NULL;

static int major_number;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;

/* status[0]=accepted packets, status[1]=dropped packets*/
static unsigned int status[2] = {0};

static struct file_operations fops = {
	.owner = THIS_MODULE
};

static unsigned int hfunc1(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff*)){
	status[1]++;
	printk("*** Packet Dropped ***\n");
	return NF_DROP;
}

static unsigned int hfunc2(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff*))
{
	status[0]++;
	printk("*** Packet Accepted ***\n");
	return NF_ACCEPT;
}

ssize_t display(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	int ret;
	/*we store the status like that -> accepted,dropped (with a comma between the two numbers)*/
	ret = scnprintf(buf, PAGE_SIZE, "%u,%u", status[0], status[1]);
	return ret;
}

ssize_t modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	int temp;
	if (sscanf(buf, "%u", &temp) == 1){
		if(temp == 0){
			status[0] = 0; status[1] = 0;
		}
	}	
	return count;	
}

static DEVICE_ATTR(sysfs_att, S_IRWXO , display, modify);

static int __init sysfs_example_init(void)
{
	//create char device
	major_number = register_chrdev(0, "Sysfs_Device", &fops);\
	if (major_number < 0)
		return -1;
		
	//create sysfs class
	sysfs_class = class_create(THIS_MODULE, "Sysfs_class");
	if (IS_ERR(sysfs_class))
	{
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}
	
	//create sysfs device
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, "sysfs_class" "_" "sysfs_Device");	
	if (IS_ERR(sysfs_device))
	{
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}
	
	//create sysfs file attributes	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr))
	{
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}

	nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	
	/*registering forward hook function*/
	nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	nfho->hook 	= (nf_hookfn*)hfunc1;		
	nfho->hooknum 	= NF_INET_FORWARD;		
	nfho->pf 	= PF_INET;			
	nfho->priority = NF_IP_PRI_FIRST;			
	nf_register_hook(nfho);

	/*registering local_in hook function*/
	nfho1 = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	nfho1->hook 	= (nf_hookfn*)hfunc2;		
	nfho1->hooknum 	= NF_INET_LOCAL_IN;		
	nfho1->pf 	= PF_INET;			
	nfho1->priority = NF_IP_PRI_FIRST;			
	nf_register_hook(nfho1);

	/*registering local_out hook function*/
	nfho2 = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	nfho2->hook 	= (nf_hookfn*)hfunc2;		
	nfho2->hooknum 	= NF_INET_LOCAL_OUT;		
	nfho2->pf 	= PF_INET;			
	nfho2->priority = NF_IP_PRI_FIRST;			
	nf_register_hook(nfho2);

	return 0;
}

static void __exit sysfs_example_exit(void)
{
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr);
	device_destroy(sysfs_class, MKDEV(major_number, 0));
	class_destroy(sysfs_class);
	unregister_chrdev(major_number, "Sysfs_Device");
	nf_unregister_hook(nfho);
	kfree(nfho);
	nf_unregister_hook(nfho1);
	kfree(nfho1);
	nf_unregister_hook(nfho2);
	kfree(nfho2);
}

module_init(sysfs_example_init);
module_exit(sysfs_example_exit);
