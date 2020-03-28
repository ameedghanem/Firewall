#ifndef _LOG_LIST_H_
#define _LOG_LIST_H_

#include "fw.h"



/*
 *
 *
 */
int my_open(struct inode *_inode, struct file *_file);


/*
 *
 *
 */
ssize_t my_read(struct file *filp, char *buff, size_t length, loff_t *offp);


/*
 *
 *
 */
__be32 get_proxy_ip( __be32 ip);


/*
 *
 *
 */
__be16 get_proxy_port( __be16 src_port, __be16 dst_port);


/*
 *
 *
 */
int is_pass_to_proxy( __be32 src_port, __be32 dst_port);


/*
 *
 *
 */
void set_packet_fields(rule_t* pkt, direction_t direction, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, ack_t ack, prot_t protocol);


/*
 *
 *
 */
unsigned int hfunc(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff*));


/*
 *
 *
 */
void change_ip_for_syn_ack_packet(struct sk_buff* skb, struct tcphdr* tcph, __be32 src_ip, __be16 sport);


/*
 *
 *
 */
unsigned int hfunc_local_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff*));


/*
 *
 *
 */
ssize_t display_rules(struct device *dev, struct device_attribute *attr, char *buf);


/*
 *
 *
 */
ssize_t modify_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);


/*
 *
 *
 */
ssize_t modify_reset(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);


/*
 *
 *
 */
ssize_t display_conns(struct device *dev, struct device_attribute *attr, char *buf);


/*
 *
 *
 */
ssize_t modify_conns(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);


/*
 *
 *
 */
ssize_t modify_ftp(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);





#endif // _LOG_LIST_H_