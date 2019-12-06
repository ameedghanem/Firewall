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
#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ameed Ghanem");

#define DEVICE_FILE_NAME "fw_log"

typedef struct log_list_t{
    log_row_t* row;
    struct log_list_t* next;
} log_list_t;

static log_list_t* log_table;
static struct nf_hook_ops *nfho = NULL;


static rule_t rule_table[MAX_RULES];
static int last_rule; //index of the last rule
static ssize_t rule_status[2];// = {0};
static char input[4096];
//rule_status[0] = NF_DROP;
//rule_status[1] = last_rule;

//  Warning:
//  Dont remove this funcion because u will most propably need it!

/*static void set_rule(int index, char* rule_name, direction_t direction, __be32 src_ip, __be32 src_prefix_mask, __u8 src_prefix_size, __be32 dst_ip, __be32 dst_prefix_mask, __u8 dst_prefix_size, __be16 src_port, __be16 dst_port, __u8 protocol, ack_t ack, __u8 action){
	strcpy(rule_table[index].rule_name, rule_name);
	rule_table[index].direction = DIRECTION_ANY;
	rule_table[index].src_ip = src_ip;
	rule_table[index].src_prefix_mask = src_prefix_mask;
	rule_table[index].src_prefix_size = src_prefix_size;
	rule_table[index].dst_ip = dst_ip;
	rule_table[index].dst_prefix_mask = dst_prefix_mask;
	rule_table[index].dst_prefix_size = dst_prefix_size;
	rule_table[index].src_port = src_port;
	rule_table[index].dst_port = dst_port;
	rule_table[index].protocol = protocol;
	rule_table[index].ack = ack; 
	rule_table[index].action = action;
}*/

//set_rule(0, "loopback", DIRECTION_ANY, , (2^8-1) << 24, 8, , (2^8-1) << 24, 8, 0, 0, PROT_ANY, ACK_ANY, NF_ACCEPT);


static int log_equals(log_row_t* r1, log_row_t* r2){
	return r1->protocol==r2->protocol && r1->action==r2->action && r1->src_ip==r2->src_ip && r1->dst_ip==r2->dst_ip && r1->src_port==r2->src_port && r1->dst_port==r2->dst_port && r1->reason==r2->reason;
}

static int rule_equal(rule_t* r1, rule_t* r2){
	return !strcmp(r1->rule_name, r2->rule_name) && r1->direction==r2->direction && r1->src_port==r2->src_port && r1->dst_port==r2->dst_port && r1->ack==r2->ack;
}

static int* check_rule(rule_t* rule){
	int i;
	for(i=0; i<=last_rule; i++){
		if(rule_equal(&rule_table[i], rule)){
			rule_status[0] = rule_table[i].action;
			rule_status[1] = i;
			return rule_status;
		}
	}
	return rule_status;
}


static log_list_t* find_node(log_list_t* head, log_row_t* row){
    if(log_equals(head->row, row)){
        return head;
    }
    if(!head->next){//If it reahed the end of our chanel-list and didnt find the wanted one, then it returns NULL
        return NULL;
    }
    return find_node(head->next, row);
}



static void set_row_in_list(log_list_t* head, log_row_t* row){
	log_list_t* node;
	log_list_t* new_node = NULL;
	node = find_node(head, row);
    if(node){
    	node->row->count++;
    	return;
    }
    new_node = (log_list_t*)kmalloc(sizeof(log_list_t), GFP_KERNEL);
    new_node->row = row;
    if(!head){
        head = new_node;
        return;
    }
    if(!find_node(head, row)){
        head->next = new_node;
    }
}


static void add_row(unsigned long timestamp, unsigned char protocol, unsigned char action, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, reason_t reason){
	log_row_t* new_row = (log_row_t*)kmalloc(sizeof(log_row_t), GFP_KERNEL);
	new_row->timestamp = timestamp;
	new_row->protocol = protocol;
	new_row->action = action;
	new_row->src_ip = src_ip;
	new_row->dst_ip = dst_ip;
	new_row->src_port = src_port;
	new_row->dst_port = dst_port;
	new_row->reason = reason;
	new_row->count = 0;
	set_row_in_list(log_table, new_row);
}


static void freeList(log_list_t* head){
    if(head != NULL){
        freeList(head->next);
        kfree(head->row);
        kfree(head);
    }
    head = NULL;
}



static char rule_string[4096];
static char log_string[4096];

static char* rule_to_str(rule_t* rule){
	char protocolS[10], actionS[10], src_ipS[10], dst_ipS[10], src_portS[10], dst_portS[10], src_prefixS[10], dst_prefixS[10] ,ackS[10], directionS[10];
	sprintf(protocolS, "%d", rule->protocol);
	sprintf(actionS, "%d", rule->action);
	sprintf(src_ipS, "%d", rule->src_ip);
	sprintf(dst_ipS, "%d", rule->dst_ip);
	sprintf(src_portS, "%d", rule->src_port);
	sprintf(dst_portS, "%d", rule->dst_port);
	sprintf(src_prefixS, "%d", rule->src_prefix_size);
	sprintf(dst_prefixS, "%d", rule->dst_prefix_size);
	sprintf(ackS, "%d", rule->ack);
	sprintf(directionS, "%d", rule->direction);
	//concatinatin
	strcat(rule_string, rule->rule_name);
	strcat(rule_string, "$");
	strcat(rule_string, directionS);
	strcat(rule_string, "$");
	strcat(rule_string, src_ipS);
	strcat(rule_string, "$");
	strcat(rule_string, src_prefixS);
	strcat(rule_string, "$");
	strcat(rule_string, dst_ipS);
	strcat(rule_string, "$");
	strcat(rule_string, dst_prefixS);
	strcat(rule_string, "$");
	strcat(rule_string, src_portS);
	strcat(rule_string, "$");
	strcat(rule_string, dst_portS);
	strcat(rule_string, "$");
	strcat(rule_string, protocolS);
	strcat(rule_string, "$");
	strcat(rule_string, ackS);
	strcat(rule_string, "$");
	strcat(rule_string, actionS);
	strcat(rule_string, "#");
	return rule_string;
}


static void ruleTable_to_str(void){
	int i=0;
	rule_string[0] = '\0';
	for(i=0; i<=last_rule; i++){
		rule_to_str(&rule_table[i]);
	}
}


static char* log_to_str(log_row_t* entry){
	char timestampS[10], protocolS[10], actionS[10], src_ipS[10], dst_ipS[10], src_portS[10], dst_portS[10], reasonS[10], countS[10];
	sprintf(timestampS, "%ld", entry->timestamp);
	sprintf(protocolS, "%d", entry->protocol);
	sprintf(actionS, "%d", entry->action);
	sprintf(src_ipS, "%d", entry->src_ip);
	sprintf(dst_ipS, "%d", entry->dst_ip);
	sprintf(src_portS, "%d", entry->src_port);
	sprintf(dst_portS, "%d", entry->dst_port);
	sprintf(reasonS, "%d", entry->reason);
	sprintf(countS, "%d", entry->count);
	//concatinating
	strcat(log_string, timestampS);
	strcat(log_string, "$");
	strcat(log_string, protocolS);
	strcat(log_string, "$");
	strcat(log_string, actionS);
	strcat(log_string, "$");
	strcat(log_string, src_ipS);
	strcat(log_string, "$");
	strcat(log_string, dst_ipS);
	strcat(log_string, "$");
	strcat(log_string, src_portS);
	strcat(log_string, "$");
	strcat(log_string, dst_portS);
	strcat(log_string, "$");
	strcat(log_string, reasonS);
	strcat(log_string, "$");
	strcat(log_string, countS);
	strcat(log_string, "#");
	return log_string;
}


static int major_number;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;

static unsigned int isEmpty = 1;
//static int str_len;

int my_open(struct inode *_inode, struct file *_file)
{
	return 0;
}

/* Our custom read function  for file_operations --------------------- */
ssize_t my_read(struct file *filp, char *buff, size_t length, loff_t *offp) {
	ssize_t num_of_bytes, total_bytes;
	//char* data = log_to_str(log_table);
	log_list_t* head = log_table;
	while(head != NULL){
		log_to_str(head->row);
		num_of_bytes = strlen(log_string);
		total_bytes += num_of_bytes;
		if (copy_to_user(buff, log_string, num_of_bytes)) { // Send the data to the user through 'copy_to_user'
        	return -EFAULT;
    	}
	}
	return total_bytes;
	/*num_of_bytes = (str_len < length) ? str_len : length;
    
    if (num_of_bytes == 0) { // We check to see if there's anything to write to the user
    	return 0;
	}
    
    if (copy_to_user(buff, buffer_index, num_of_bytes)) { // Send the data to the user through 'copy_to_user'
        return -EFAULT;
    } else { // fuction succeed, we just sent the user 'num_of_bytes' bytes, so we updating the counter and the string pointer index
        str_len -= num_of_bytes;
        buffer_index += num_of_bytes;
        return num_of_bytes;
    }
	return -EFAULT; // Should never reach here*/
}


static int compute_num(char* num){
	int i, res = 0, factor=1;
	for(i=strlen(num)-1; i >= 0; i--){
		res += (num[i]-'0')*factor;
		factor *= 10;
	}
	return res;
}


static void reset_string(char* str){
	int i;
	for(i=0; i<strlen(str); i++){
		str[i] = '\0';
	}
}

static void process_rule(char* data){
	int i=0;
	char* found;
	last_rule++;
	while( (found = strsep(&data,"$")) != NULL ){
		switch(i){
			case 0:
				strcpy(rule_table[last_rule].rule_name, found);
				break;

			case 1:
				rule_table[last_rule].direction = htonl(compute_num(found));
				break;

			case 2:
				rule_table[last_rule].src_ip = htonl(compute_num(found));
				break;

			case 3:
				rule_table[last_rule].src_prefix_mask = htonl(compute_num(found));
				break;

			case 4:
				rule_table[last_rule].src_prefix_size = htonl(compute_num(found));
				break;

			case 5:
				rule_table[last_rule].dst_ip = htonl(compute_num(found));
				break;

			case 6:
				rule_table[last_rule].dst_prefix_mask = htonl(compute_num(found));
				break;

			case 7:
				rule_table[last_rule].dst_prefix_size = htonl(compute_num(found));
				break;

			case 8:
				rule_table[last_rule].src_port = htons(compute_num(found));
				break;

			case 9:
				rule_table[last_rule].dst_port = htons(compute_num(found));
				break;

			case 10:
				rule_table[last_rule].protocol = htons(compute_num(found));
				break;

			case 11:
				rule_table[last_rule].ack = htonl(compute_num(found));
				break;

			case 12:
				rule_table[last_rule].action = htons(compute_num(found));
				break;
			default:
				return;
		}
		i++;
	}
}


static void parse_rules(char* data){
	char *found, line[100] = {0};
	while( (found = strsep(&data,"#")) != NULL ){
		process_rule(found);
		reset_string(line);
	}
}



static unsigned int hfunc(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff*)){
	direction_t dir;
	unsigned int sport, dport;
	struct iphdr* iph;
	struct tcphdr* tcph;
	struct udphdr* udph;
	//struct ethhdr* hdr;
	struct timeval now;
	unsigned int temp, second, minute, hour;
	__u32 pkt_src, pkt_dst;
	/*hdr = eth_hdr(skb);
	if(!hdr){
		return NF_DROP;
	}
	src_mac = hdr->h_source;
	dst_mac = hdr->h_dest;
	if(src_mac == ETH1 && dst_mac == ETH2)
		dir = DIRECTION_OUT;
	if(src_mac == ETH2 && dst_mac == ETH1)
		dir = DIRECTION_IN;*/
	iph = ip_hdr(skb);
	if(!iph){
		return NF_DROP;
	}
	pkt_src = iph->saddr; pkt_dst = iph->daddr;//no need to htnol cause we do intend to hold them with the network order!!
	if(pkt_src == ETH1 && pkt_dst == ETH2)
		dir = DIRECTION_OUT;
	if(pkt_src == ETH2 && pkt_dst == ETH1)
		dir = DIRECTION_IN;
	if(iph->version != IP_VERSION)
		return NF_ACCEPT;
	if(pkt_src == LO && pkt_dst == LO)
		return NF_ACCEPT;		
	if(iph->protocol == IPPROTO_TCP){
		tcph = tcp_hdr(skb);
		if(!tcph){
			return NF_DROP;
		}
		sport = tcph->source;
		dport = tcph->dest;
		if( (tcph->fin | tcph->urg | tcph->psh) == (TCPHDR_FIN | TCPHDR_URG | TCPHDR_PSH) ){
			do_gettimeofday(&now);
			add_row(now.tv_sec, PROT_TCP, dir, pkt_src, pkt_dst, sport, dport, REASON_XMAS_PACKET);
			return NF_DROP; //The Christmas packt!
		}
	}else if(iph->protocol == IPPROTO_UDP){
		udph = udp_hdr(skb);
		if(!udph){
			return NF_DROP;
		}
		sport = udph->source;
		dport = udph->dest;
	}else if(iph->protocol == IPPROTO_ICMP){
		sport = 0, dport = 0;
	}else{
		return NF_ACCEPT;
	}
	//write to the rule driver which will write the result to log driver
	do_gettimeofday(&now);
	/*temp = now.tv_sec;
	second = temp%60;
	temp /= 60;
	minute = temp%60;
	temp /= 60;
	hour = temp%24 + 2;*/
	
	return NF_ACCEPT;
}


static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = my_open,
	.read = my_read
};

ssize_t display_rules(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	ruleTable_to_str();
	return scnprintf(buf, PAGE_SIZE, "%s\n", rule_string);
}


ssize_t modify_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	//char data[4096];
	if(sscanf(buf, "%s", input) == -1){
		printk("Failed to load the rules!\n");
		return 0;
	}
	parse_rules(input);
	return strlen(input);
}

ssize_t modify_reset(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	int temp;
	if (sscanf(buf, "%u", &temp) == 1){
		isEmpty = 1;
		freeList(log_table);
	}
	return count;	
}


static DEVICE_ATTR(rules, S_IRWXO , display_rules, modify_rules);
static DEVICE_ATTR(reset, S_IRWXO , NULL, modify_reset);

static int __init firewall_init(void)
{
	/*hook function*/
	nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	if(!nfho){
		printk("Failed to allocate hook_ops.\n");
	}
	nfho->hook 	= (nf_hookfn*)hfunc;		
	nfho->hooknum 	= NF_INET_FORWARD;		
	nfho->pf 	= PF_INET;			
	nfho->priority = NF_IP_PRI_FIRST;			
	if(nf_register_hook(nfho)){
		printk("Hook function registration failed.\n");
		return 0;
	}
	/************************************************************************************************/
	//create char device
	major_number = register_chrdev(0, "firewall", &fops);\
	if (major_number < 0)
		return -1;
		
	//create sysfs class
	sysfs_class = class_create(THIS_MODULE, "fw");
	if (IS_ERR(sysfs_class))
	{
		unregister_chrdev(major_number, "firewall");
		return -1;
	}
	
	//create rules device
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, "rules");	
	if (IS_ERR(sysfs_device))
	{
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "firewall");
		return -1;
	}
	
	//create log device
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, "log");	
	if (IS_ERR(sysfs_device))
	{
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "firewall");
		return -1;
	}

	//create sysfs file attributes	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_rules.attr))
	{
		device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_rules.attr);
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "firewall");
		return -1;
	}
	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_reset.attr))
	{
		device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_reset.attr);
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "firewall");
		return -1;
	}
	/************************************************************************************************/
	return 0;
}

static void __exit firewall_exit(void)
{
	/************************************************************************************************/
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_reset.attr);
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_rules.attr);
	device_destroy(sysfs_class, MKDEV(major_number, 0));
	class_destroy(sysfs_class);
	unregister_chrdev(major_number, "firewall");
	/************************************************************************************************/
	nf_unregister_hook(nfho);
	kfree(nfho);
}

module_init(firewall_init);
module_exit(firewall_exit);