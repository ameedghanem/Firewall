
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

static struct nf_hook_ops *nfho = NULL;
static struct nf_hook_ops *nfho1 = NULL;
static struct nf_hook_ops *nfho2 = NULL;


static unsigned int hfunc1(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff*)){
	printk("*** Packet Dropped ***\n"); 
	return NF_DROP;
}

static unsigned int hfunc2(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff*)){
	printk("*** Packet Accepted ***\n");
	return NF_ACCEPT;
}

static int __init FW_init(void)
{
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

static void __exit FW_exit(void)
{
	/*unregistering hook functions and freeing the memory allocated for the nf_hook_ops*/
	nf_unregister_hook(nfho);
	kfree(nfho);
	nf_unregister_hook(nfho1);
	kfree(nfho1);
	nf_unregister_hook(nfho2);
	kfree(nfho2);
}

module_init(FW_init);
module_exit(FW_exit);
