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
#include <linux/socket.h>
#include "../includes/fw.h"
#include "../includes/conns_table.h"
#include "../includes/rules_parser.h"
#include "../includes/log_list.h"


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Statefull Firewall");
MODULE_AUTHOR("Ameed S. Ghanem");

static struct nf_hook_ops *nfho = NULL;
static struct nf_hook_ops *nfho_out = NULL;

static struct class* sysfs_class = NULL;
static struct device* rules_device = NULL;
static struct device* conns_device = NULL;
static struct device* reset_log_device = NULL;
static struct device* ftp_device = NULL;
static struct device* log_device = NULL;

static int major_number;

static int conns_on = 0;
static int rules_on = 0;
static int last_rule = 0;
static int str_len = 0;

static conns_table_t* connection_table = NULL;
static log_list_t* log_table = NULL;
static rule_t rule_table[MAX_RULES];

static char action_and_reason[2] = {0};
char rule_string[4096];
static char input[4096];
static char mytemp_rules[4096] = {0};
static char mytemp_conns[4096] = {0};
char* buffer_index = NULL;
char* temp = NULL;



//==========================
//	fop's implementation
//==========================



int my_open(struct inode *_inode, struct file *_file)
{
	temp = log2str(log_table);
	buffer_index = temp;
	str_len = strlen(temp);
	return 0;
}


/* Our custom read function  for file_operations --------------------- */
ssize_t my_read(struct file *filp, char *buff, size_t length, loff_t *offp) {
	ssize_t num_of_bytes;
	if(log_table == NULL){
		return 0;
	}
	num_of_bytes = (str_len < length) ? str_len : length;
    if (num_of_bytes == 0) { // We check to see if there's anything to write to the user
    	kfree(temp);
    	temp = NULL;
    	return 0;
	}
    
    if (copy_to_user(buff, buffer_index, num_of_bytes)) { // Send the data to the user through 'copy_to_user'
    	kfree(temp);
    	temp = NULL;
        return -EFAULT;
    } else { // fuction succeed, we just sent the user 'num_of_bytes' bytes, so we updating the counter and the string pointer index
        str_len -= num_of_bytes;
        buffer_index += num_of_bytes;
        if(str_len == 0){
        	kfree(temp);
        	temp = NULL;
        }
        return num_of_bytes;
    }
	return -EFAULT;
}


//returns the proxy ip of the given ip
__be32 get_proxy_ip( __be32 ip){
	if(ip == ETH1)
		return VLAN_1_IFACE;
	return VLAN_2_IFACE;
}


//returns thr proxy port according to the given src/dst ports
__be16 get_proxy_port( __be16 src_port, __be16 dst_port){
	if(src_port == 80 || dst_port == 80)
		return 800;
	/*else if(src_port == 20 || dst_port == 20)
		return 209;*/
	else if(src_port == 21 || dst_port == 21)
		return 210;
	return 0;
}

int is_pass_to_proxy( __be32 src_port, __be32 dst_port){
	int case1 = src_port == 80 || dst_port == 80;
	//int case2 = src_port == 20 || dst_port == 20;
	int case3 = src_port == 21 || dst_port == 21;
	return case1 || case3;// || case3;
}

void set_packet_fields(rule_t* pkt, direction_t direction, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, ack_t ack, prot_t protocol){
	pkt->direction = direction;
	pkt->src_ip = src_ip; pkt->dst_ip = dst_ip; 
	pkt->src_port = src_port; pkt->dst_port = dst_port;
	pkt->ack = ack;
	pkt->protocol = protocol;
}


void read_ftp_device(char* data){
	int i=0, num;
	char* found;
	__be32 src_ip, dst_ip;
	__be16 src_port, dst_port, proxy_port;
	TCP_STATE conn_state1, conn_state2;
	struct timeval now;
	do_gettimeofday(&now);
	src_ip = 0; dst_ip = 0; src_port = 0; dst_port = 0; proxy_port = 0;
	conn_state1 = 0; conn_state2 = 0;
	while( (found = strsep(&data,"$")) != NULL ){
		if(strlen(found) == 0)
			return;
		num = compute_num2(found);
		switch(i){
			case 0:
				if(!isNumber2(found)){
					if(stohi2(found) == 0){
						printk("Invalid IP address\n");
						//last_rule = 0;
						return ;
					}
				}
				src_ip = stohi2(found);//htonl(num);//htonl(compute_num2(found));
				break;

			case 1:
				src_port = htons(num);
				break;

			case 2:
				if(!isNumber2(found)){
					if(stohi2(found) == 0){
						printk("Invalid IP address\n");
						//last_rule = 0;
						return ;
					}
				}
				dst_ip = stohi2(found);//htonl(compute_num2(found));
				break;

			case 3:
				dst_port = htons(num);
				break;

			default:
				//{}
			i++;
		}
	}
	add_conn(&connection_table, src_ip, src_port, dst_ip, dst_port, TCP_STT_LISTEN, TCP_STT_CLOSED, now.tv_sec);
}


unsigned int hfunc(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff*)){
	struct timeval now;
	struct iphdr* iph;
	struct tcphdr* tcph;
	struct udphdr* udph;
	unsigned int sport, dport;
	direction_t dir;
	int curr_reason;//, tcpData_length;
	rule_t curr_packet;
	connection_t curr_conn, *found;//, *temp;
	//conns_table_t* found = NULL;
	tcph = NULL; udph = NULL; iph = NULL; dir = DIRECTION_ANY, curr_reason=0 ;
	do_gettimeofday(&now);
	sport = 0; dport = 0;
	if(!skb){
		return NF_ACCEPT;
	}
	iph = ip_hdr(skb);
	if(!iph){
		printk("Failed to parse the IP Header\n");
		return NF_DROP;
	}
	if(connection_table != NULL){
			remove_closed_and_timed_out_conns(&connection_table, now.tv_sec);
	}
	if(iph->saddr == LO && iph->daddr == LO){//if it's a loopback packet we simply accept it wethout logging !!
		return NF_ACCEPT;
	}
	dir = DIRECTION_ANY;
	if(iph->saddr == ETH1 && iph->daddr == ETH2){
		dir = DIRECTION_OUT;
	}
	else if(iph->saddr == ETH2 && iph->daddr == ETH1){
		dir = DIRECTION_IN;
	}

	//accept any IPv6 packet wethout logging
	if(iph->version != IP_VERSION){
		return NF_ACCEPT;
	}

	//accept any non-(TCP, UDP, ICMP) protocol wethout logging
	if (iph->protocol != IPPROTO_ICMP && iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	//TCP case
	if(iph->protocol == IPPROTO_TCP){
		tcph = (struct tcphdr*)(skb->data + (iph->ihl << 2));
		if(!tcph){
			printk("Failed to parse the TCP Header\n");
			return NF_DROP;
		}
		sport = ntohs(tcph->source);
		dport = ntohs(tcph->dest);

		if(tcph->urg && tcph->psh && tcph->fin){//XMAS PACKET
			add_row(&log_table, now.tv_sec, PROT_TCP, NF_DROP, iph->saddr, iph->daddr, sport, dport, REASON_XMAS_PACKET);
			return NF_DROP;
		}

		set_packet_fields(&curr_packet, dir, iph->saddr, iph->daddr, sport, dport, tcph->ack, PROT_TCP);
		curr_conn.src_ip = iph->saddr; curr_conn.src_port = sport;
		curr_conn.dst_ip = iph->daddr; curr_conn.dst_port = dport;
		if(curr_packet.ack == 0){
			check_rule(rule_table, &curr_packet, &last_rule, action_and_reason);
			if(action_and_reason[0] == NF_ACCEPT){
				if(!find_conn(connection_table, &curr_conn)){
					action_and_reason[1] = REASON_SYN_PACKET;
					add_conn(&connection_table, curr_packet.src_ip, sport, curr_packet.dst_ip, dport, TCP_STT_SYN_SENT, TCP_STT_LISTEN, now.tv_sec);
					if(is_pass_to_proxy(sport, dport)){
						change_src_ip(skb, get_proxy_ip(curr_packet.src_ip), get_proxy_port(curr_packet.src_port, curr_packet.dst_port), 0);
					}
				}else{
					action_and_reason[0] = NF_DROP;
					action_and_reason[1] = CONN_ALREADY_EXISTS;
				}
			}
		}else{
			if(!check_conn(connection_table, iph->saddr, sport, curr_packet.dst_ip, dport, get_flag(tcph), now.tv_sec)){
				action_and_reason[0] = NF_DROP; action_and_reason[1] = REASON_NO_CONN_EXIST;
			}else{
				found = find_one_conn(connection_table, &curr_conn);
				if(found){
					update_state(connection_table, curr_packet.src_ip, get_flag(tcph));
					if(is_pass_to_proxy(sport, dport)){
						//update_state(connection_table, curr_packet.src_ip, get_flag(tcph));
						change_src_ip(skb,found->proxy_src_ip, found->proxy_src_port, 0);//change_src_ip(skb, get_proxy_ip(curr_packet.src_ip), found->proxy_src_port, 0);
					}
					action_and_reason[0] = NF_ACCEPT; action_and_reason[1] = REASON_FOUND_CONN;
					if(connection_table != NULL){
						remove_closed_and_timed_out_conns(&connection_table, now.tv_sec);
					}
				}
			}
		}
		add_row(&log_table, now.tv_sec, PROT_TCP, action_and_reason[0], iph->saddr, curr_packet.dst_ip, ntohs(tcph->source), curr_packet.dst_port, action_and_reason[1]);
		return action_and_reason[0];//action;
	}
	if(iph->protocol == IPPROTO_UDP){
		udph = (struct udphdr*)((char*)iph + (iph->ihl << 2));
		if(!udph){
			printk("Failed to parse the UDP Header\n");
			return NF_DROP;
		}
		sport = ntohs(udph->source); dport = ntohs(udph->dest);
	}else if(iph->protocol == IPPROTO_ICMP){
		dport = 0; sport = 0;
	}
	set_packet_fields(&curr_packet, dir, iph->saddr, iph->daddr, sport, dport, ACK_ANY, iph->protocol);
	check_rule(rule_table, &curr_packet, &last_rule, action_and_reason);
	add_row(&log_table, now.tv_sec, iph->protocol, action_and_reason[0], iph->saddr, iph->daddr, sport, dport, action_and_reason[1]);
	return action_and_reason[0];
} 


/*
 *this function is reponsible about mofifying src ip/port for the syn-ack packet when redirecting the proxy conns for the 1st time.
 */
void change_ip_for_syn_ack_packet(struct sk_buff* skb, struct tcphdr* tcph, __be32 src_ip, __be16 sport){
	__be32 orig_ip;
	orig_ip = src_ip == VLAN_1_IFACE ? ETH2: ETH1;
	if(sport == 800){
		change_src_ip(skb, orig_ip, 80, 1);
		update_state(connection_table, orig_ip, get_flag(tcph));
	}else if(sport == 210){
		change_src_ip(skb, orig_ip, 21, 1);
		update_state(connection_table, orig_ip, get_flag(tcph));
	}else if(sport == 209){
		change_src_ip(skb, orig_ip, 20, 1);
		update_state(connection_table, orig_ip, get_flag(tcph));
	}
}


unsigned int hfunc_local_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff*)){
	struct iphdr* iph;
	struct tcphdr* tcph;
	unsigned int sport, dport;
	int tcpData_length;
	connection_t curr_conn;
	connection_t* proxy_conn = NULL;
	iph = NULL; tcph = NULL; sport=0; dport=0;
	if(!skb){
		printk("skb is NULL !\n");
		return NF_ACCEPT;
	}
	iph = ip_hdr(skb);
	if(!iph){
		printk("Failed to parse the IP Header\n");
		return NF_ACCEPT;
	}
	if(iph->protocol == IPPROTO_TCP){
		tcpData_length = (skb->len - ((iph->ihl) << 2));//we subtract the header length from the the tcp packet length
		tcph = (struct tcphdr*)(skb->data + (iph->ihl << 2));
		if(!tcph){
			printk("Failed to parse the TCP Header\n");
			return NF_ACCEPT;
		}
		
		sport = ntohs(tcph->source);
		dport = ntohs(tcph->dest);
		curr_conn.src_ip = iph->saddr; curr_conn.src_port = sport;
		curr_conn.dst_ip = iph->daddr; curr_conn.dst_port = dport;

		proxy_conn = find_conn_by_proxy(connection_table, &curr_conn);
		if(proxy_conn != NULL){
			if(proxy_conn->proxy_src_port == 0){
				proxy_conn->proxy_src_port = sport;
			}
			change_src_ip(skb, proxy_conn->dst_ip, proxy_conn->dst_port, 1);
			return NF_ACCEPT;
		}
	}
	return NF_ACCEPT;
}


static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = my_open,
	.read = my_read
};

ssize_t display_rules(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs_rules show implementation
{
	char* str = "no rules";
	if(last_rule == 0){
		return scnprintf(buf, PAGE_SIZE, "%s\n", str);
	}
	ruleTable_to_str(rule_table, rule_string, &last_rule);
	return scnprintf(buf, PAGE_SIZE, "%s\n", rule_string);
}


ssize_t modify_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs_rules store implementation
{
	if(sscanf(buf, "%s", input) == -1){
		printk("Failed to load the rules!\n");
		return 0;
	}
	strcpy(mytemp_rules, input);
	if(rules_on == 1)
		reset_rules(rule_table, &last_rule);
	parse_rules(rule_table, mytemp_rules, &last_rule);
	rules_on = 1;
	return strlen(input);
}


ssize_t modify_reset(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs_reset store implementation
{
	int input;
	if (sscanf(buf, "%u", &input) == 1){
		if(log_table != NULL){
			printk("standing to free the log table\n");
			freeList(log_table);
			log_table = NULL;
			if(temp != NULL){
				kfree(temp);
				temp = NULL;
			}
		}
	}
	return count;	
}


ssize_t display_conns(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs_conns show implementation
{
	int len;
	char* conns, *str = "no conns";
	conns = NULL;
	len = conns_length(connection_table);
	if(connection_table == NULL){
		return scnprintf(buf, PAGE_SIZE, "%s\n", str);
	}
	conns = encode_conns(connection_table);
	return scnprintf(buf, PAGE_SIZE, "%s\n", conns);
}


ssize_t modify_conns(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs_conns store implementation
{
	if(sscanf(buf, "%s", input) == -1){
		printk("Failed to load the connection table!\n");
		return 0;
	}
	strcpy(mytemp_conns, input);
	parse_conn(&connection_table, mytemp_conns);
	conns_on = 1;
	return strlen(input);
}


ssize_t modify_ftp(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs_ftp store implementation
{
	char data_conn_str[50];
	if(sscanf(buf, "%s", data_conn_str) == -1){
		printk("Failed to load the ftp port command\n");
		return 0;
	}
	read_ftp_device(data_conn_str);
	return strlen(data_conn_str);
}

//define sysfs attribue for the various devices the firewall has
static DEVICE_ATTR(rules, S_IROTH | S_IWOTH , display_rules, modify_rules);
static DEVICE_ATTR(reset, S_IROTH | S_IWOTH , NULL, modify_reset);
static DEVICE_ATTR(conns, S_IROTH | S_IWOTH , display_conns, modify_conns);
static DEVICE_ATTR(ftp_port_cmd, S_IROTH | S_IWOTH , NULL, modify_ftp);


//====================================
//	Firewall Module Initialization
//====================================
static int __init firewall_init(void)
{
	nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	if(!nfho){
		printk("Hook ops. allocation failed\n");
		return -1;
	}
	nfho->hook 	= (nf_hookfn*)hfunc;		
	nfho->hooknum 	= NF_INET_PRE_ROUTING;		
	nfho->pf 	= PF_INET;			
	nfho->priority = NF_IP_PRI_FIRST;			
	if(nf_register_hook(nfho)){
		printk("Hook function registration failed.\n");
		return -1;;
	}
	nfho_out = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	if(!nfho_out){
		printk("Hook ops. allocation failed\n");
		return -1;
	}
	nfho_out->hook 	= (nf_hookfn*)hfunc_local_out;		
	nfho_out->hooknum 	= NF_INET_LOCAL_OUT;		
	nfho_out->pf 	= PF_INET;		
	nfho_out->priority = NF_IP_PRI_FIRST;			
	if(nf_register_hook(nfho_out)){
		printk("Hook function registration failed\n");
		return -1;
	}

	//create char device
	major_number = register_chrdev(0, FW_CHARDEV_NAME, &fops);
	if (major_number < 0)
		return -1;
		
	//create sysfs class
	sysfs_class = class_create(THIS_MODULE, FW_CLASS);
	if (IS_ERR(sysfs_class))
	{
		unregister_chrdev(major_number, FW_CHARDEV_NAME);
		return -1;
	}
	
	
	//create log device
	log_device = device_create(sysfs_class, NULL, MKDEV(major_number, MINOR_LOG), NULL, DEVICE_NAME_LOG);	
	if (IS_ERR(log_device))
	{
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, FW_CHARDEV_NAME);
		return -1;
	}

	
	//create rules device
	rules_device = device_create(sysfs_class, NULL, MKDEV(major_number, MINOR_RULES), NULL, DEVICE_NAME_RULES);	
	if (IS_ERR(rules_device))
	{
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, FW_CHARDEV_NAME);
		return -1;
	}
	
	//create sysfs file attributes	
	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr))
	{
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, FW_CHARDEV_NAME);
		return -1;
	}
				
	//create log device
	reset_log_device = device_create(sysfs_class, NULL, MKDEV(major_number, MINOR_RESET), NULL, DEVICE_NAME_RESET_LOG);	
	if (IS_ERR(reset_log_device))
	{
		//device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, FW_CHARDEV_NAME);
		return -1;
	}


	if (device_create_file(reset_log_device, (const struct device_attribute *)&dev_attr_reset.attr))
	{
		//device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RESET));
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));	
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, FW_CHARDEV_NAME);
		return -1;
	}


	//create conn device
	conns_device = device_create(sysfs_class, NULL, MKDEV(major_number, MINOR_CONNS), NULL, DEVICE_NAME_CONNS);	
	if (IS_ERR(conns_device))
	{
		//device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));
		device_remove_file(reset_log_device, (const struct device_attribute *)&dev_attr_reset.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RESET));
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));	
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, FW_CHARDEV_NAME);
		return -1;
	}


	if (device_create_file(conns_device, (const struct device_attribute *)&dev_attr_conns.attr))
	{
		//device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));
		device_remove_file(reset_log_device, (const struct device_attribute *)&dev_attr_reset.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RESET));
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_CONNS));
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, FW_CHARDEV_NAME);
		return -1;
	}

	ftp_device = device_create(sysfs_class, NULL, MKDEV(major_number, MINOR_FTP_PORT_CMD), NULL, DEVICE_NAME_FTP_PORT_CMD);	
	if (IS_ERR(ftp_device))
	{
		//device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));
		device_remove_file(reset_log_device, (const struct device_attribute *)&dev_attr_reset.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RESET));
		device_remove_file(conns_device, (const struct device_attribute *)&dev_attr_conns.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_CONNS));
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, FW_CHARDEV_NAME);
		return -1;
	}


	if (device_create_file(ftp_device, (const struct device_attribute *)&dev_attr_ftp_port_cmd.attr))
	{
		//device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));
		device_remove_file(reset_log_device, (const struct device_attribute *)&dev_attr_reset.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RESET));
		device_remove_file(conns_device, (const struct device_attribute *)&dev_attr_conns.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_CONNS));
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_FTP_PORT_CMD));
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, FW_CHARDEV_NAME);
		return -1;
	}

	return 0;
}

static void __exit firewall_exit(void)
{
	//remove device files

	device_remove_file(reset_log_device, (const struct device_attribute *)&dev_attr_reset.attr);
	device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
	device_remove_file(conns_device, (const struct device_attribute *)&dev_attr_conns.attr);
	device_remove_file(ftp_device, (const struct device_attribute *)&dev_attr_ftp_port_cmd.attr);

	//remove devices
	//device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
	device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));
	device_destroy(sysfs_class, MKDEV(major_number, MINOR_RESET));
	device_destroy(sysfs_class, MKDEV(major_number, MINOR_CONNS));
	device_destroy(sysfs_class, MKDEV(major_number, MINOR_FTP_PORT_CMD));
	device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));

	//remove class
	class_destroy(sysfs_class);

	//remove char device
	unregister_chrdev(major_number, FW_CHARDEV_NAME);

	//remove nf_hook structs and free them
	nf_unregister_hook(nfho);
	nf_unregister_hook(nfho_out);
	kfree(nfho);
	kfree(nfho_out);

	//freeing allocated resources.
	if(list_length(log_table) != 0)
		freeList(log_table);
	if(temp != NULL)
		kfree(temp);
	if(connection_table != NULL)
		freeConns(connection_table);
}

module_init(firewall_init);
module_exit(firewall_exit);