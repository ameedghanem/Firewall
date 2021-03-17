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
#include "fw.h"
#include "conns_table.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ameed S. Ghanem");

#define ROW_LENGTH 80

/*struct chardev_info{
	spinlock_t lock;
};
unsigned long flags;

static struct chardev_info device_info;*/

static int conns_on;
static int toRemove = 0;

conns_table_t* connection_table;
ssize_t number_of_entries = 0;
static log_list_t* log_table;

//static char* log_string;
static struct nf_hook_ops *nfho = NULL;
static struct nf_hook_ops *nfho_out = NULL;

static rule_t rule_table[MAX_RULES];
static int rules_on;
static int last_rule;
static char input[4096];
static char mytemp[4096] = {0};

char action_and_reason[2] = {0};


//=====================================
//	The log list auxilary functions
//=====================================
static int log_equals(log_row_t* r1, log_row_t* r2){
	return r1->protocol==r2->protocol && r1->action==r2->action && r1->src_ip==r2->src_ip && r1->dst_ip==r2->dst_ip && r1->src_port==r2->src_port && r1->dst_port==r2->dst_port && r1->reason==r2->reason;
}



static log_list_t* find_node(log_list_t* head, log_row_t* row){
	if(head == NULL){
		return NULL;
	}
    if(log_equals(head->row, row)){
        return head;
    }
    if(!head->next){//If it reahed the end of our chanel-list and didnt find the wanted one, then it returns NULL
        return NULL;
    }
    return find_node(head->next, row);
}

//used for debugging
/*static void printList(){
	log_list_t* head = log_table;
	while(head != NULL){
		printk("%ld  ", head->row->timestamp);
		head = head->next;
	}
	printk("\n");
}*/


static void set_row_in_list(log_row_t* row){
	//printk("int set row\n");
	log_list_t *node, *head;
	log_list_t* new_node = NULL;
	head = log_table;
	node = find_node(head, row);
	//if node found, modify the count and timestamp
    if(node != NULL){
    	//printList();
    	node->row->timestamp = row->timestamp;
    	node->row->count++;
    	kfree(row);
    	return;
    }
    new_node = (log_list_t*)kmalloc(sizeof(log_list_t), GFP_ATOMIC);
    new_node->row = row;
    new_node->next = NULL;
   	// if head is empty then we set the new node to be the head
    if(!head){
    	//printList();
        log_table = new_node;
        return;
    }
    //reach the last node and set it's next node to be the new node.
    while(head->next != NULL)
    	head = head->next;
    head->next = new_node;
    //printList();
}


static void add_row(unsigned long timestamp, unsigned char protocol, unsigned char action, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, reason_t reason){
	//printk("got: src = %u<->%d,  dst = %u<->%d\n", src_ip, src_port, dst_ip, dst_port);
	log_row_t* new_row = (log_row_t*)kmalloc(sizeof(log_row_t), GFP_ATOMIC);
	new_row->timestamp = timestamp;
	new_row->protocol = protocol;
	new_row->action = action;
	new_row->src_ip = src_ip;
	new_row->dst_ip = dst_ip;
	new_row->src_port = src_port;
	new_row->dst_port = dst_port;
	new_row->reason = reason;
	new_row->count = 1;
	set_row_in_list(new_row);
}


static void freeList(log_list_t* head){
    if(head != NULL){
        freeList(head->next);
        kfree(head->row);
        kfree(head);
    }
    head = NULL;
}


static int num_of_entries(log_list_t* head){
	if(head == NULL)
		return 0;
	return 1 +  num_of_entries(head->next);
}


static int list_length(log_list_t* head){
	return num_of_entries(head)*ROW_LENGTH;
}

//char* logSTR = NULL;

static char* log2str(log_list_t* head){
	int len;
	char timestampS[20], protocolS[10], actionS[10], src_ipS[12], dst_ipS[12], src_portS[10], dst_portS[10], reasonS[10], countS[10];
	char* logSTR = NULL;
	log_list_t* phead = head;
	struct tm tm_val;
	len = list_length(head);
	printk("log length = %d\n", len);
	if(len == 0){		
		return "";
	}
	logSTR = kcalloc(len, sizeof(char), GFP_ATOMIC);
	if(logSTR == NULL)
		return NULL;
	memset(logSTR, '\0', len);
	while(phead != NULL){
		time_to_tm(phead->row->timestamp, 0, &tm_val);
		snprintf(timestampS, 100, "%d/%d/%ld %02d:%02d:%02d", tm_val.tm_mday, tm_val.tm_mon + 1,
                    1900 + tm_val.tm_year, tm_val.tm_hour+2, tm_val.tm_min,
                    tm_val.tm_sec);
		sprintf(protocolS, "%d", phead->row->protocol);
		sprintf(actionS, "%d", phead->row->action);
		sprintf(src_ipS, "%u", phead->row->src_ip);		snprintf(dst_ipS, 12, "%u", phead->row->dst_ip);
		sprintf(src_portS, "%u", phead->row->src_port);
		sprintf(dst_portS, "%u", phead->row->dst_port);
		sprintf(reasonS, "%d", phead->row->reason);
		sprintf(countS, "%d", phead->row->count);

		strcat(logSTR, timestampS);
		strcat(logSTR, "$");
		strcat(logSTR, src_ipS);
		strcat(logSTR, "$");
		strcat(logSTR, dst_ipS);
		strcat(logSTR, "$");
		strcat(logSTR, src_portS);
		strcat(logSTR, "$");
		strcat(logSTR, dst_portS);
		strcat(logSTR, "$");
		strcat(logSTR, protocolS);
		strcat(logSTR, "$");
		strcat(logSTR, actionS);
		strcat(logSTR, "$");
		strcat(logSTR, reasonS);
		strcat(logSTR, "$");
		strcat(logSTR, countS);
		strcat(logSTR, "#");
		phead = phead->next;
	}
	//printk(" -> %s\n", logSTR);
	return logSTR;

}


//===========================
// The Rules-Table Prser
//===========================


//return 1 iff ack flag is valid
static int isValidPort( __be16 port, __be16 rule_port){
	if(rule_port == 1023)
		return (port > 1023) && (port == rule_port);
	if(rule_port > 0 && rule_port <= 1023)
		return (port > 0) && (port <= 1023) && (port == rule_port);
	return 0;//should never reach this line
}

//return 1 iff protocol is valid
static int isValidProtocol(prot_t protocol){
	return protocol == PROT_TCP || protocol == PROT_UDP || protocol == PROT_ICMP || protocol == PROT_ANY || protocol == PROT_OTHER;
}

//return 1 iff action is valid
static int isValidAction(int action){
	return action == NF_DROP || action == NF_ACCEPT;
}

//return 1 iff direction is valid
static int isValidDirection(direction_t direct){
		return direct == DIRECTION_ANY || direct == DIRECTION_OUT || direct == DIRECTION_IN;
}

//return 1 iff ack flag is valid
static int isValidAck(ack_t a){
	return a == ACK_ANY || a == ACK_YES || a == ACK_NO;
}

//compares between two given rules
static int rule_equal(rule_t* r1, rule_t* r2){
	int case1 = (r1->direction==r2->direction || r1->direction==DIRECTION_ANY);
	int case2 = ( ( (r1->src_port==r2->src_port) && isValidPort(r1->src_port, r2->src_port) ) || r1->src_port==PORT_ANY);
	int case3 = ((r1->dst_port==r2->dst_port && isValidPort(r1->dst_port, r2->dst_port)) || r1->dst_port==PORT_ANY);
	int case4 = (r1->ack==r2->ack || r1->ack==ACK_ANY);
	int case5 = ( (r1->src_ip & r1->src_prefix_mask)==(r2->src_ip & r1->src_prefix_mask) || r1->src_ip==0);
	int case6 = ((r1->dst_ip & r1->dst_prefix_mask)==(r2->dst_ip & r1->dst_prefix_mask) || r1->dst_ip==0);
	int case7 = (r1->protocol == r2->protocol || r1->protocol == PROT_ANY);
	return case1 && case2 && case3 & case4 && case5 && case6 && case7;
}


/*checks the rule agains the rule table
 *action_and_reason[0] = action, action_and_reason[1] = reason
 */
static void check_rule(rule_t* rule){
	int i;
	if(rules_on == 0){
		//return REASON_FW_INACTIVE;
		action_and_reason[0] = NF_DROP; action_and_reason[1] = REASON_FW_INACTIVE;
		return ;
	}
	for(i=0; i<=last_rule; i++){
		if(rule_equal(&rule_table[i], rule)){
			if(i == last_rule){
				action_and_reason[0] = rule_table[i].action; action_and_reason[1] = REASON_NO_MATCHING_RULE;
				return ;
			}
			action_and_reason[0] = rule_table[i].action; action_and_reason[1] = i+1; 
			return ;
		}
		if(!rule_equal(&rule_table[i], rule)){
			if(i == last_rule){
				action_and_reason[0] = rule_table[i].action; action_and_reason[1] = REASON_NO_MATCHING_RULE;
				return ;
			}
		}
	}
	//return -1;
}

//resets a string
void reset_string(char* str){
	int i;
	for(i=0; i<strlen(str); i++){
		str[i] = '\0';
	}
}

static char rule_string[4096];

static void pack_rule(char* rulename, char* direction, char* src_ip, char* src_prefix, char* dst_ip, char* dst_prefix,
					 char* protocol, char* src_port, char* dst_port, char* ack, char* action){

	strcat(rule_string, rulename);
	strcat(rule_string, "$");
	strcat(rule_string, direction);
	strcat(rule_string, "$");
	strcat(rule_string, src_ip);
	strcat(rule_string, "$");
	strcat(rule_string, src_prefix);
	strcat(rule_string, "$");
	strcat(rule_string, dst_ip);
	strcat(rule_string, "$");
	strcat(rule_string, dst_prefix);
	strcat(rule_string, "$");
	strcat(rule_string, protocol);
	strcat(rule_string, "$");
	strcat(rule_string, src_port);
	strcat(rule_string, "$");
	strcat(rule_string, dst_port);
	strcat(rule_string, "$");
	strcat(rule_string, ack);
	strcat(rule_string, "$");
	strcat(rule_string, action);
	strcat(rule_string, "#");
}


//converting the rule table to string
static char* rule_to_str(rule_t* rule){
	char protocolS[10], actionS[10], src_ipS[10], dst_ipS[10], src_portS[10], dst_portS[10], src_prefixS[10], dst_prefixS[10] ,ackS[10], directionS[10];
	if(last_rule == 0)
		return NULL;
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
	/*strcat(rule_string, rule->rule_name);
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
	strcat(rule_string, protocolS);
	strcat(rule_string, "$");
	strcat(rule_string, src_portS);
	strcat(rule_string, "$");
	strcat(rule_string, dst_portS);
	strcat(rule_string, "$");
	strcat(rule_string, ackS);
	strcat(rule_string, "$");
	strcat(rule_string, actionS);
	strcat(rule_string, "#");*/
	pack_rule(rule->rule_name, directionS, src_ipS, src_prefixS, dst_ipS, dst_prefixS, protocolS, src_portS, dst_portS, ackS, actionS);
	return rule_string;
}


//returns 1 iff the argument number is a valid number
int isNumber(char* str){
	int i;
	for(i=0; i<strlen(str); i++){
		if(str[i] > '9' || str[i] < '0')
			return 0;
	}
	return 1;
}

//computes the number, if succedded it returns the value, else it returns 0
int compute_num(char* num){
	int i, res = 0, factor=1;
	for(i=strlen(num)-1; i >= 0; i--){
		res += (num[i]-'0')*factor;
		factor *= 10;
	}
	return res;
}


static void ruleTable_to_str(void){
	int i=0;
	rule_string[0] = '\0';
	for(i=0; i<=last_rule; i++){
		rule_to_str(&rule_table[i]);
	}
}

//shifts the string right
void shift_str(char* str, int num){
	int i;
	int len = strlen(str);
	for(i=len+num-1; i >= num; i--){
		str[i] = str[i-num];
	}
}


//==========================
//	fop implementation
//==========================

static int major_number;
static struct class* sysfs_class = NULL;
static struct device* rules_device = NULL;
static struct device* conns_device = NULL;
static struct device* reset_log_device = NULL;
static struct device* ftp_device = NULL;
static struct device* log_device = NULL;

static int str_len = 0;
char* buffer_index = NULL;
char* temp = NULL;

int my_open(struct inode *_inode, struct file *_file)
{
	//temp = log2str(log_table);
	//buffer_index = kcalloc(strlen(temp), sizeof(char), GFP_ATOMIC);
	//strcpy(buffer_index, temp);
	//kfree(temp);
	//str_len = strlen(temp);
	//printk("done opening");
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
    	//printk("in my read 473\n");
    	kfree(temp);
    	temp = NULL;
    	return 0;
	}
    
    if (copy_to_user(buff, buffer_index, num_of_bytes)) { // Send the data to the user through 'copy_to_user'
    	//printk("in my read 479\n");
    	kfree(temp);
    	temp = NULL;
        return -EFAULT;
    } else { // fuction succeed, we just sent the user 'num_of_bytes' bytes, so we updating the counter and the string pointer index
        str_len -= num_of_bytes;
        buffer_index += num_of_bytes;
        //printk("in my read 485\n");
        if(str_len == 0){
        	kfree(temp);
        	temp = NULL;
        }
        return num_of_bytes;
    }
    /*printk("in my read 489\n");
    kfree(temp);
    temp = NULL;*/
	return -EFAULT;
	//kfree(temp);
	//temp = NULL;
	//return 0;
}

//return 1 iff c is a digit
int isdigit(char c){
	return c <= '9' && c >= '0';
}

//returns the ip address in network byte order
unsigned int stohi(char *ip){
	char c;
	unsigned int integer;
	int val;
	int i,j=0;
	integer=0;
	c = *ip;
	for (j=0;j<4;j++) {
		if (!isdigit(c)){  //first char is 0
			return (0);
		}
		val=0;
		for (i=0;i<3;i++) {
			if (isdigit(c)) {
				val = (val * 10) + (c - '0');
				c = *++ip;
			} else
				break;
		}
		if(val<0 || val>255){
			return (0);	
		}	
		if (c == '.') {
			integer=(integer<<8) | val;
			c = *++ip;
		} 
		else if(j==3 && c == '\0'){
			integer=(integer<<8) | val;
			break;
		}
			
	}
	if(c != '\0'){
		return (0);	
	}
	return (htonl(integer));
}


static int isValidMask(int x){
	int i, masks[25] = {0xffffffff, 0xfffffffe, 0xfffffffc, 0xfffffff8, 0xfffffff0, 0xffffffe0, 0xffffffc0, 0xffffff80, 0xffffff00, 0xfffffe00, 0xfffffc00, 0xfffff800, 0xfffff000, 0xffffe000, 0xffffc000, 0xffff8000, 0xffff0000, 0xfffe0000, 0xfffc0000, 0xfff80000, 0xff000000, 0xfe000000, 0xfc000000, 0xf8000000, 0xf0000000};
	for(i=0; i<25; i++){
		if(x == masks[i])
			return 1;
	}
	return 0;
}

static int isValidPrefixSize(int x){
	return x <= 32 && x >= 8;
}

static void reset_rules(rule_t* rules_table){
	last_rule = 0;
}


//parsing the given rule
static void process_rule(char* data){
	int i=0, num;
	char* found;
	while( (found = strsep(&data,"$")) != NULL ){
		num = compute_num(found);
		switch(i){
			case 0:
				strcpy(rule_table[last_rule].rule_name, found);
				break;

			case 1:
				rule_table[last_rule].direction = num;//compute_num(found);
				if(!isValidDirection(num)){
					printk("Invalid direction number\n");
					last_rule = 0;
					return ;
				}
				break;

			case 2:
				if(!isNumber(found)){
					if(stohi(found) == 0){
						printk("Invalid IP address\n");
						last_rule = 0;
						return ;
					}
				}
				rule_table[last_rule].src_ip = stohi(found);//htonl(num);//htonl(compute_num(found));
				break;

			case 3:
				if(num != 0){
					if(!isValidPrefixSize(num)){
						printk("Invalid IP address prefix size\n");
						last_rule = 0;
						return ;
					}
				}
				rule_table[last_rule].src_prefix_size = num;//compute_num(found);
				break;

			case 4:
				if(num != 0){
					if(!isValidMask(num)){
						printk("Invalid IP Subnet Mask\n");
						last_rule = 0;
						return ;
					}
				}
				rule_table[last_rule].src_prefix_mask = htonl(num);//htonl(compute_num(found));
				break;

			case 5:
				if(!isNumber(found)){
					if(stohi(found) == 0){
						printk("Invalid IP address\n");
						last_rule = 0;
						return ;
					}
				}
				rule_table[last_rule].dst_ip = stohi(found);//htonl(compute_num(found));
				break;

			case 6:
				if(num != 0){
					if(!isValidPrefixSize(num)){
						printk("Invalid IP address prefix size\n");
						last_rule = 0;
						return ;
					}
				}
				rule_table[last_rule].dst_prefix_size = num;//compute_num(found);
				break;

			case 7:
				if(num != 0){
					if(!isValidMask(num)){
						printk("Invalid IP Subnet Mask\n");
						last_rule = 0;
						return ;
					}
				}
				rule_table[last_rule].dst_prefix_mask = htonl(num);//htonl(num);//htonl(compute_num(found));
				break;

			case 8:
				//rule_table[last_rule].protocol = compute_num(found);
				if(!isValidProtocol(num)){
					printk("Invalid protocol number: %d\n", num);
					last_rule = 0;
					return ;
				}
				rule_table[last_rule].protocol = num;
				break;

			case 9:
				rule_table[last_rule].src_port = htons(num);//htons(compute_num(found));
				break;

			case 10:
				rule_table[last_rule].dst_port = htons(num);//htons(compute_num(found));
				break;

			case 11:
				rule_table[last_rule].ack = num;//compute_num(found);
				if(!isValidAck(num)){
					printk("Invalid ack flag\n");
					last_rule = 0;
					return ;
				}
				break;

			case 12:
				rule_table[last_rule].action = num;//compute_num(found);
				if(!isValidAction(num)){
					printk("Invalid action number\n");
					last_rule = 0;
					return ;
				}
				break;
			default:
				return;
		}
		i++;
		if(strlen(found) == 0)
			return;
	}
}


static void parse_rules(char* data){
	char *found;//, line[100] = {0};
	int i=0;
	while( ((found = strsep(&data,"#")) != NULL) ){
		if(strlen(found) == 0)
			return;
		process_rule(found);
		if(i != 0){
			if(last_rule == 0){
				return ;
			}
		}	
		last_rule++;
		i++;
	}
	last_rule--;
}

static int get_flag(struct tcphdr* tcph){
	if(tcph->syn && tcph->ack)
		return TCP_SYN_ACK;
	else if(tcph->fin && tcph->ack)
		return TCP_FIN_ACK;
	else if(tcph->rst && tcph->ack)
		return TCP_RST_ACK;
	else if(tcph->syn)
		return TCP_SYN;
	else if(tcph->ack)
		return TCP_ACK;
	else if(tcph->rst)
		return TCP_RST;
	else if(tcph->fin)
		return TCP_FIN;
	return TCP_NO_FLAG;
	//return tcph->ack | tcph->fin | tcph->rst | tcph->syn;
}

#if 0
void remove_closed_and_timed_out_conns(conns_table_t* conn_tab, unsigned long timestamp){
	conns_table_t *curr = NULL, *nextHead = NULL;
	curr = conn_tab;
	if(curr != NULL){
		if(curr->next != NULL)
			nextHead = curr->next;
		else{
			if((curr->conn->state == TCP_STT_CLOSED && curr->rconn->state == TCP_STT_CLOSED) || ( ((timestamp - curr->timestamp) > 15) && (curr->conn->state != TCP_STT_ESTABLISHED) ) ){
				/*kfree(head->conn); kfree(head->conn);
				kfree(head);*/
				printk("standing to free the connection table\n");
				freeConns(connection_table);
				toRemove += CONN_LENGTH;
				connection_table = NULL;
			}
		}
	}
	while(curr != NULL){
		//nextHead = curr->next;
		if(nextHead == NULL)
			return;
		if(nextHead->conn->state == TCP_STT_CLOSED || nextHead->rconn->state == TCP_STT_CLOSED || ( (timestamp - nextHead->timestamp) > 15 && nextHead->conn->state != TCP_STT_ESTABLISHED) ){
			printk("conn state = %d, rconn state = %d\n", nextHead->conn->state, nextHead->rconn->state);
			curr->next = nextHead->next;
			kfree(nextHead->conn); kfree(nextHead->conn);
			kfree(nextHead);
			toRemove += CONN_LENGTH;
		}
		curr = curr->next;
		//nextHead = nextHead->next;
	}
}
#endif

/*void remove_timed_out_conns(conns_table_t* conn_tab, unsigned long curr_timestamp){
	conns_table_t* head = NULL;
	head = conn_tab;
	while(head != NULL){
		if(curr_timestamp - head->timestamp > )

		head = head->next;
	}
}
*/


void remove_closed_and_timed_out_conns(conns_table_t** conn_tab, unsigned long timestamp){
	conns_table_t *prev, *tmp = *conn_tab;
	prev = NULL;
	printk(" in remove timeout -----> we passed %ld sec\n", timestamp - tmp->timestamp);
	if(*conn_tab != NULL){
		printk("708\n'");
		if((*conn_tab)->next == NULL){
			printk("710\n");
			if((tmp->conn->state == TCP_STT_CLOSED && tmp->rconn->state == TCP_STT_CLOSED) || ( (timestamp - tmp->timestamp) > 15 && tmp->conn->state != TCP_STT_ESTABLISHED)){
				kfree((*conn_tab)->conn); kfree((*conn_tab)->rconn);
				kfree(tmp);			
				*conn_tab = NULL;
				printk("hlllwlwl\n");
				return;
			}
		}
	}
	prev = tmp;
	while(tmp != NULL){
		if((tmp->conn->state == TCP_STT_CLOSED && tmp->rconn->state == TCP_STT_CLOSED) || ( (timestamp - tmp->timestamp) > 15 && tmp->conn->state != TCP_STT_ESTABLISHED)){
			prev->next = tmp->next;
			kfree(tmp->conn); kfree(tmp->rconn);
			kfree(tmp);
			tmp = NULL;
			toRemove += CONN_LENGTH;
			tmp = prev->next;
			continue;
		}
		prev = tmp;
		tmp = tmp->next;
	}
}


//returns the proxy ip of the given ip
__be32 get_proxy_ip( __be32 ip){
	if(ip == ETH1)
		return VLAN_1_IFACE;
	return VLAN_2_IFACE;
}

__be16 get_proxy_port( __be16 src_port, __be16 dst_port){
	if(src_port == 80 || dst_port == 80)
		return 800;
	else if(src_port == 20 || dst_port == 20)
		return 209;
	else if(src_port == 21 || dst_port == 21)
		return 210;
	return 0;
}

int is_pass_to_proxy( __be32 src_port, __be32 dst_port){
	int case1 = src_port == 80 || dst_port == 80;
	int case2 = src_port == 20 || dst_port == 20;
	int case3 = src_port == 21 || dst_port == 21;
	return case1 || case2 || case3;
}

void set_packet_fields(rule_t* pkt, direction_t direction, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, ack_t ack, prot_t protocol){
	pkt->direction = direction;
	pkt->src_ip = src_ip; pkt->dst_ip = dst_ip; 
	pkt->src_port = src_port; pkt->dst_port = dst_port;
	pkt->ack = ack;
	pkt->protocol = protocol;
}


static unsigned int hfunc(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff*)){
	struct timeval now;
	struct iphdr* iph;
	struct tcphdr* tcph;
	struct udphdr* udph;
	unsigned int sport, dport;
	direction_t dir;
	int curr_reason, tcpData_length;
	rule_t curr_packet;
	connection_t curr_conn;//, *temp;
	conns_table_t* found = NULL;
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
	/*if(in == NULL || out == NULL){
		//printk("in/out are NULL.\n");
		//return NF_DROP;
	}else{
		if(!strcmp(in->name, "lo") && !strcmp(out->name, "lo"))
			return NF_ACCEPT; //there is no need to log loopback traffic
		if(!strcmp(in->name, IN_NET_DEVICE_NAME) && !strcmp(out->name, OUT_NET_DEVICE_NAME))
			dir = DIRECTION_OUT;
		if(!strcmp(in->name, OUT_NET_DEVICE_NAME) && !strcmp(out->name, IN_NET_DEVICE_NAME))
			dir = DIRECTION_IN;
	}*/
	if(connection_table != NULL){
			printk("refreshing the connection table\n");
			remove_closed_and_timed_out_conns(&connection_table, now.tv_sec);
	}
	if(iph->saddr == LO && iph->daddr == LO){//if it's a loopback packet we simply accept it wethout logging !!
		return NF_ACCEPT;
	}
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
	if(iph->protocol == IPPROTO_TCP){
		tcph = (struct tcphdr*)(skb->data + (iph->ihl << 2));
		if(!tcph){
			printk("Failed to parse the TCP Header\n");
			return NF_DROP;
		}
		sport = ntohs(tcph->source);
		dport = ntohs(tcph->dest);
		if(tcph->urg && tcph->psh &&tcph->fin){
			add_row(now.tv_sec, PROT_TCP, NF_DROP, iph->saddr, iph->daddr, sport, dport, REASON_XMAS_PACKET);
			return NF_DROP;
		}
		set_packet_fields(&curr_packet, dir, iph->saddr, iph->daddr, sport, dport, tcph->ack, PROT_TCP);
		curr_conn.src_ip = iph->saddr; curr_conn.src_port = sport;
		curr_conn.dst_ip = iph->daddr; curr_conn.dst_port = dport;
		if(curr_packet.ack == 0){
			check_rule(&curr_packet);
			if(action_and_reason[0] == NF_ACCEPT){
				if(!find_conn(connection_table, &curr_conn)){
					action_and_reason[1] = REASON_SYN_PACKET;
					add_conn(&connection_table, curr_packet.src_ip, sport, curr_packet.dst_ip, dport, TCP_STT_SYN_SENT, TCP_STT_LISTEN, now.tv_sec);
					if(is_pass_to_proxy(sport, dport)){
						change_src_ip(skb, get_proxy_ip(curr_packet.src_ip), get_proxy_port(curr_packet.src_port, curr_packet.dst_port), 0);
						/*}else if(dport == 80){
							change_src_ip(skb, htonl(0x0a010103), 800, 0);
						}*/
						//add_conn(&connection_table, curr_packet.src_ip, curr_packet.src_port, iph->daddr, ntohs(tcph->dest), TCP_STT_SYN_SENT, TCP_STT_LISTEN, now.tv_sec);
					}
					//add_conn(&connection_table, curr_packet.src_ip, sport, curr_packet.dst_ip, dport, TCP_STT_SYN_SENT, TCP_STT_LISTEN, now.tv_sec);
				}else{
					action_and_reason[0] = NF_DROP;
					action_and_reason[1] = CONN_ALREADY_EXISTS;
				}
			}		
		}else{
			if(curr_packet.src_ip == htonl(0x0a010202) && curr_packet.src_port == 80){
				//if(iph->saddr == htonl(0x0a010203) && iph->daddr == htonl(0x0a010202)){
				if(connection_table != NULL){//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
					update_state(connection_table, curr_packet.src_ip, get_flag(tcph));
					change_src_ip(skb, htonl(0x0a010203), connection_table->conn->proxy_src_port, 0);
					printk("chnaged in the local out, proxy port = :%d\n", connection_table->conn->proxy_src_port);
				//} 
					add_row(now.tv_sec, PROT_TCP, NF_ACCEPT, iph->saddr, curr_packet.dst_ip, ntohs(tcph->source), curr_packet.dst_port, REASON_FOUND_CONN);
				}//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
				return NF_ACCEPT;
			}
			//=================================
			/*if(is_pass_to_proxy(sport, dport)){
				update_state(connection_table, curr_packet.src_ip, get_flag(tcph));
				change_src_ip(skb, get_proxy_ip(curr_packet.src_ip), get_proxy_port(curr_packet.src_port, curr_packet.dst_port), 0);
			}*/
			//=================================
			//if(!check_conn(connection_table, iph->saddr, sport, iph->daddr, dport, get_flag(tcph), now.tv_sec)){
			if(!check_conn(connection_table, iph->saddr, sport, curr_packet.dst_ip, dport, get_flag(tcph), now.tv_sec)){
				action_and_reason[0] = NF_DROP; action_and_reason[1] = REASON_NO_CONN_EXIST;
			}else{
				tcpData_length = (skb->len - ((iph->ihl) << 2));
				found = find_conn(connection_table, &curr_conn);//find_conn_by_proxy(connection_table, &curr_conn);
				if(found){
					if(is_pass_to_proxy(sport, dport)){
						update_state(connection_table, curr_packet.src_ip, get_flag(tcph));
						change_src_ip(skb, get_proxy_ip(curr_packet.src_ip), get_proxy_port(curr_packet.src_port, curr_packet.dst_port), 0);
					}
					action_and_reason[0] = NF_ACCEPT; action_and_reason[1] = REASON_FOUND_CONN;
					if(connection_table != NULL){
						remove_closed_and_timed_out_conns(&connection_table, now.tv_sec);
					}
				}
			}
		}
		add_row(now.tv_sec, PROT_TCP, action_and_reason[0], iph->saddr, curr_packet.dst_ip, ntohs(tcph->source), curr_packet.dst_port, action_and_reason[1]);
		return action_and_reason[0];//action;
	}
	if(iph->protocol == IPPROTO_UDP){
		udph = (struct udphdr*)((char*)iph + (iph->ihl << 2));//(skb->data + (iph->ihl << 2));
		if(!udph){
			printk("Failed to parse the UDP Header\n");
			return NF_DROP;
		}
		sport = ntohs(udph->source); dport = ntohs(udph->dest);
	}else if(iph->protocol == IPPROTO_ICMP){
		dport = 0; sport = 0;
	}
	set_packet_fields(&curr_packet, dir, iph->saddr, iph->daddr, sport, dport, ACK_ANY, iph->protocol);
	check_rule(&curr_packet);
	add_row(now.tv_sec, iph->protocol, action_and_reason[0], iph->saddr, iph->daddr, sport, dport, action_and_reason[1]);
	return action_and_reason[0];
} 


/*
 *this function is reponsible about mofifying src ip/port for the syn-ack packet when redirecting the proxy conns for the 1st time.
 */
void change_ip_for_syn_ack_packet(struct sk_buff* skb, struct tcphdr* tcph, __be32 src_ip, __be16 sport){
	__be32 orig_ip;
	orig_ip = src_ip == htonl(0x0a010103) ? ETH2: ETH1;
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


static unsigned int hfunc_local_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff*)){
	struct iphdr* iph;
	struct tcphdr* tcph;
	unsigned int sport, dport;
	int tcpData_length;
	connection_t curr_conn, *temp;//, *found;
	//conns_table_t* conn_entry = NULL;
	temp = NULL;
	iph = NULL; tcph = NULL; sport=0; dport=0;
	if(!skb){
		printk("skn is NULL !\n");
		return NF_ACCEPT;
	}
	iph = ip_hdr(skb);
	if(!iph){
		printk("Failed to parse the IP Header\n");
		return NF_DROP;
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
		printk("I'm in the local out, sport=%d, dport=%d\n", sport,dport);
		//====================================================================================
		//check if the current packet is produced by the proxies. (either the ftp or the http)
		//====================================================================================
		//??????????????????????????????????????????????????????????????????????????????????????????????????????????????????
		//we need at first to verify that the given packet doest exist in the connection table, if not we return drop..
		//??????????????????????????????????????????????????????????????????????????????????????????????????????????????????
		curr_conn.src_ip = iph->saddr; curr_conn.src_port = sport;
		curr_conn.dst_ip = iph->daddr; curr_conn.dst_port = dport;
		/*temp = find_conn_by_proxy(connection_table, &curr_conn);
		if(temp != NULL){// && temp->state == TCP_STT_ESTABLISHED){
			change_src_ip(skb, temp->src_ip, temp->src_port, 1);
			return NF_ACCEPT;
		}*/
//#if 0
		if(connection_table != NULL){
			change_ip_for_syn_ack_packet(skb, tcph, iph->saddr, sport);
		}
		if(connection_table != NULL){
			if(iph->saddr == htonl(0x0a010203) && iph->daddr == htonl(0x0a010202) && dport == 80){
				change_src_ip(skb, htonl(0x0a010101), connection_table->conn->src_port, 1);
				connection_table->conn->proxy_src_port = sport;
				//update_state(connection_table, htonl(0x0a010101), get_flag(tcph));
			}
		}
		
		/*if(sport == 800){
			printk("Changing =================>>>>>>>>>>>>>>\n");
			change_src_ip(skb, htonl(0x0a010202), 80, 1);
			update_state(connection_table, htonl(0x0a010202), get_flag(tcph));
			//update_state()
			printk("changed to: src_port = %d\n", ntohs(tcph->source));
			return NF_ACCEPT;
		}else if(sport == 210){
			printk("Changing =================>>>>>>>>>>>>>>\n");
			change_src_ip(skb, htonl(0x0a010202), 21, 1);
			update_state(connection_table, htonl(0x0a010202), get_flag(tcph));
			//update_state()
			printk("changed to: src_port = %d\n", ntohs(tcph->source));
			return NF_ACCEPT;
		}else if(sport == 209){
			printk("Changing =================>>>>>>>>>>>>>>\n");
			change_src_ip(skb, htonl(0x0a010202), 20, 1);
			update_state(connection_table, htonl(0x0a010202), get_flag(tcph));
			//update_state()
			printk("changed to: src_port = %d\n", ntohs(tcph->source));
			return NF_ACCEPT;
		}*/
		if(connection_table != NULL){
			if(iph->saddr == htonl(0x0a010103) && iph->daddr == htonl(0x0a010101) && sport == 800){
				change_src_ip(skb, htonl(0x0a010202), 80, 1);
				connection_table->conn->proxy_src_port = sport;
			}
		}
//#endif
		//return NF_DROP;
/*		if(iph->saddr == VLAN_1_IFACE && iph->daddr == ETH1){
			if(sport == 800){
				curr_conn.proxy_src_ip = VLAN_1_IFACE; curr_conn.proxy_src_port = sport;
				curr_conn.proxy_dst_ip = ETH1; curr_conn.proxy_dst_port = dport;
				//found = find_conn_by_proxy(connection_table, &curr_conn);//============
				//if(found)//============
					change_src_ip(skb, ETH2, 80, 1);
				//if(tcph->ack == 0)
				//	connection_table->conn->proxy_src_port = sport;
				//if(connection_table != NULL)
				//	update_state(connection_table, ETH2, get_flag(tcph));
				return NF_ACCEPT;
			}
		}

		if(iph->saddr == VLAN_2_IFACE && iph->daddr == ETH2){
			if(dport == HTTP_PORT){
				curr_conn.proxy_src_ip = VLAN_2_IFACE; curr_conn.proxy_src_port = sport;
				curr_conn.proxy_dst_ip = ETH2; curr_conn.proxy_dst_port = HTTP_PORT;
				//found = find_conn_by_proxy(connection_table, &curr_conn);//============
				//if(found){//============
					change_src_ip(skb, ETH1, found->src_port, 1);
					//if(tcph->ack == 0)
					//	found->proxy_src_port = sport;//syn packet
					//if(connection_table != NULL)
					//	update_state(connection_table, ETH1, get_flag(tcph));
					return NF_ACCEPT;
				//}//============
			}
		}	*/	
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
	ruleTable_to_str();
	return scnprintf(buf, PAGE_SIZE, "%s\n", rule_string);
}


ssize_t modify_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs_rules store implementation
{
	if(sscanf(buf, "%s", input) == -1){
		printk("Failed to load the rules!\n");
		return 0;
	}
	strcpy(mytemp, input);
	if(rules_on == 1)
		reset_rules(rule_table);
	parse_rules(mytemp);
	rules_on = 1;
	return strlen(input);
}


ssize_t modify_reset(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs_reset store implementation
{
	int input;//, i, len;
	if (sscanf(buf, "%u", &input) == 1){
		if(log_table != NULL){
			printk("before freeing the log table\n");
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
	len -= toRemove;
	printk("conns length = %d\n", len);
	if(connection_table == NULL){//if(len == 0){
		return scnprintf(buf, PAGE_SIZE, "%s\n", str);
	}
	conns = encode_conns(connection_table);
	return scnprintf(buf, PAGE_SIZE, "%s\n", conns);
	//return 1;
}


ssize_t modify_conns(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs_conns store implementation
{
	if(sscanf(buf, "%s", input) == -1){
		printk("Failed to load the rules!\n");
		return 0;
	}
	strcpy(mytemp, input);
	//if(conns_on == 1)
	//	reset_rules(rule_table);
	parse_conn(&connection_table, mytemp);
	conns_on = 1;
	return strlen(input);
}


ssize_t modify_ftp(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs_ftp store implementation
{
	char data_conn_str[50];
	if(sscanf(buf, "%s", data_conn_str) == -1){
		printk("Failed to load the rules!\n");
		return 0;
	}
	//strcpy(, data_conn_str);
	//if(conns_on == 1)
	//	reset_rules(rule_table);
	//==============================
	// need to allocte a new connection entry in the connection table
	//==============================
	//add_conn(&connection_table, src_ip, src_port, dst_ip, dst_port, TCP_STT_CLOSED, TCP_STT_SYN_SENT);
	//parse_conn(&connection_table, mytemp);
	//conns_on = 1;
	return strlen(input);
}

//define sysfs attribue for the various devices the firewall has
static DEVICE_ATTR(rules, S_IROTH | S_IWOTH , display_rules, modify_rules);
static DEVICE_ATTR(reset, S_IROTH | S_IWOTH , NULL, modify_reset);
static DEVICE_ATTR(conns, S_IROTH | S_IWOTH , display_conns, modify_conns);
static DEVICE_ATTR(ftp_port_cmd, S_IROTH | S_IWOTH , NULL, modify_ftp);


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
	major_number = register_chrdev(0, FW_CHARDEV_NAME, &fops);\
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
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, FW_CHARDEV_NAME);
		return -1;
	}
				
	//create log device
	reset_log_device = device_create(sysfs_class, NULL, MKDEV(major_number, MINOR_RESET), NULL, DEVICE_NAME_RESET_LOG);	
	if (IS_ERR(reset_log_device))
	{
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, FW_CHARDEV_NAME);
		return -1;
	}


	if (device_create_file(reset_log_device, (const struct device_attribute *)&dev_attr_reset.attr))
	{
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RESET));		
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, FW_CHARDEV_NAME);
		return -1;
	}


	//create conn device
	conns_device = device_create(sysfs_class, NULL, MKDEV(major_number, MINOR_CONNS), NULL, DEVICE_NAME_CONNS);	
	if (IS_ERR(conns_device))
	{
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));
		device_remove_file(reset_log_device, (const struct device_attribute *)&dev_attr_reset.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RESET));	
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, FW_CHARDEV_NAME);
		return -1;
	}


	if (device_create_file(conns_device, (const struct device_attribute *)&dev_attr_conns.attr))
	{
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));
		device_remove_file(reset_log_device, (const struct device_attribute *)&dev_attr_reset.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RESET));
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_CONNS));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, FW_CHARDEV_NAME);
		return -1;
	}

	ftp_device = device_create(sysfs_class, NULL, MKDEV(major_number, MINOR_FTP_PORT_CMD), NULL, DEVICE_NAME_FTP_PORT_CMD);	
	if (IS_ERR(ftp_device))
	{
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));
		device_remove_file(reset_log_device, (const struct device_attribute *)&dev_attr_reset.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RESET));
		device_remove_file(conns_device, (const struct device_attribute *)&dev_attr_conns.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_CONNS));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, FW_CHARDEV_NAME);
		return -1;
	}


	if (device_create_file(ftp_device, (const struct device_attribute *)&dev_attr_ftp_port_cmd.attr))
	{
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));
		device_remove_file(reset_log_device, (const struct device_attribute *)&dev_attr_reset.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RESET));
		device_remove_file(conns_device, (const struct device_attribute *)&dev_attr_conns.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_CONNS));
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_FTP_PORT_CMD));
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
	device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
	device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));
	device_destroy(sysfs_class, MKDEV(major_number, MINOR_RESET));
	device_destroy(sysfs_class, MKDEV(major_number, MINOR_CONNS));
	device_destroy(sysfs_class, MKDEV(major_number, MINOR_FTP_PORT_CMD));

	//remove class
	class_destroy(sysfs_class);

	//remove char devuce
	unregister_chrdev(major_number, FW_CHARDEV_NAME);

	//remove nf_hook structs and free them
	nf_unregister_hook(nfho);
	nf_unregister_hook(nfho_out);
	kfree(nfho);
	kfree(nfho_out);

	//freeing allocated resources.
	if(log_table != NULL)
		freeList(log_table);
	if(temp != NULL)
		kfree(temp);
	if(connection_table != NULL)
		freeConns(connection_table);
}

module_init(firewall_init);
module_exit(firewall_exit);