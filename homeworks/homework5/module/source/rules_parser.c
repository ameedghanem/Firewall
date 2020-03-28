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
#include "../includes/rules_parser.h"


//return 1 iff ack flag is valid
int isValidPort( __be16 port, __be16 rule_port){
	if(rule_port == 1023)
		return (port > 1023);
	if(rule_port > 0 && rule_port <= 1023)
		return (port > 0) && (port <= 1023) && (port == rule_port);
	return 0;//should never reach this line
}

//return 1 iff protocol is valid
int isValidProtocol(prot_t protocol){
	return protocol == PROT_TCP || protocol == PROT_UDP || protocol == PROT_ICMP || protocol == PROT_ANY || protocol == PROT_OTHER;
}

//return 1 iff action is valid
int isValidAction(int action){
	return action == NF_DROP || action == NF_ACCEPT;
}

//return 1 iff direction is valid
int isValidDirection(direction_t direct){
		return direct == DIRECTION_ANY || direct == DIRECTION_OUT || direct == DIRECTION_IN;
}

//return 1 iff ack flag is valid
int isValidAck(ack_t a){
	return a == ACK_ANY || a == ACK_YES || a == ACK_NO;
}

//return 1 iff x is a valid subnet mask
int isValidMask(int x){
	int i, masks[25] = {0xffffffff, 0xfffffffe, 0xfffffffc, 0xfffffff8, 0xfffffff0, 0xffffffe0, 0xffffffc0, 0xffffff80, 0xffffff00, 0xfffffe00, 0xfffffc00, 0xfffff800, 0xfffff000, 0xffffe000, 0xffffc000, 0xffff8000, 0xffff0000, 0xfffe0000, 0xfffc0000, 0xfff80000, 0xff000000, 0xfe000000, 0xfc000000, 0xf8000000, 0xf0000000};
	for(i=0; i<25; i++){
		if(x == masks[i])
			return 1;
	}
	return 0;
}

//return 1 iff x is a valid prefix mask
int isValidPrefixSize(int x){
	return x <= 32 && x >= 8;
}

//compares between two given rules
int rule_equal(rule_t* r1, rule_t* r2){
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
void check_rule(rule_t* rule_tab, rule_t* rule, int* last_r, char* action_and_reason){
	int i;
	if(*last_r == 0){
		//return REASON_FW_INACTIVE;
		action_and_reason[0] = NF_DROP; action_and_reason[1] = REASON_FW_INACTIVE;
		return ;
	}
	for(i=0; i<=*last_r; i++){
		if(rule_equal(&rule_tab[i], rule)){
			if(i == *last_r){
				action_and_reason[0] = rule_tab[i].action; action_and_reason[1] = REASON_NO_MATCHING_RULE;
				return ;
			}
			action_and_reason[0] = rule_tab[i].action; action_and_reason[1] = i+1; 
			return ;
		}
		if(!rule_equal(&rule_tab[i], rule)){
			if(i == *last_r){
				action_and_reason[0] = rule_tab[i].action; action_and_reason[1] = REASON_NO_MATCHING_RULE;
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

void pack_rule(char* rule_str, char* rulename, char* direction, char* src_ip, char* src_prefix, char* dst_ip, char* dst_prefix,
					 char* protocol, char* src_port, char* dst_port, char* ack, char* action){

	strcat(rule_str, rulename);
	strcat(rule_str, "$");
	strcat(rule_str, direction);
	strcat(rule_str, "$");
	strcat(rule_str, src_ip);
	strcat(rule_str, "$");
	strcat(rule_str, src_prefix);
	strcat(rule_str, "$");
	strcat(rule_str, dst_ip);
	strcat(rule_str, "$");
	strcat(rule_str, dst_prefix);
	strcat(rule_str, "$");
	strcat(rule_str, protocol);
	strcat(rule_str, "$");
	strcat(rule_str, src_port);
	strcat(rule_str, "$");
	strcat(rule_str, dst_port);
	strcat(rule_str, "$");
	strcat(rule_str, ack);
	strcat(rule_str, "$");
	strcat(rule_str, action);
	strcat(rule_str, "#");
}


//converting the rule table to string
void rule_to_str(rule_t* rule, char* rule_str, int* last_r){
	char protocolS[10], actionS[10], src_ipS[10], dst_ipS[10], src_portS[10], dst_portS[10], src_prefixS[10], dst_prefixS[10] ,ackS[10], directionS[10];
	if(*last_r == 0)
		return;
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
	pack_rule(rule_str, rule->rule_name, directionS, src_ipS, src_prefixS, dst_ipS, dst_prefixS, protocolS, src_portS, dst_portS, ackS, actionS);
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


void ruleTable_to_str(rule_t* rule_tab, char* rule_str, int* last_r){
	int i=0;
	rule_str[0] = '\0';
	for(i=0; i<=*last_r; i++){
		rule_to_str(&rule_tab[i], rule_str, last_r);
	}
}


int isdigit(char c){
	return c <= '9' && c >= '0';
}

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


void reset_rules(rule_t* rules_table, int* last_r){
	*last_r = 0;
}


//parsing the given rule
void process_rule(rule_t* rule_tab, char* data, int* last_r){
	int i=0, num;
	char* found;
	while( (found = strsep(&data,"$")) != NULL ){
		num = compute_num(found);
		switch(i){
			case 0:
				strcpy(rule_tab[*last_r].rule_name, found);
				break;

			case 1:
				rule_tab[*last_r].direction = num;
				if(!isValidDirection(num)){
					printk("Invalid direction number\n");
					*last_r = 0;
					return ;
				}
				break;

			case 2:
				if(!isNumber(found)){
					if(stohi(found) == 0){
						printk("Invalid IP address\n");
						*last_r = 0;
						return ;
					}
				}
				rule_tab[*last_r].src_ip = stohi(found);
				break;

			case 3:
				if(num != 0){
					if(!isValidPrefixSize(num)){
						printk("Invalid IP address prefix size\n");
						*last_r = 0;
						return ;
					}
				}
				rule_tab[*last_r].src_prefix_size = num;
				break;

			case 4:
				if(num != 0){
					if(!isValidMask(num)){
						printk("Invalid IP Subnet Mask\n");
						*last_r = 0;
						return ;
					}
				}
				rule_tab[*last_r].src_prefix_mask = htonl(num);
				break;

			case 5:
				if(!isNumber(found)){
					if(stohi(found) == 0){
						printk("Invalid IP address\n");
						*last_r = 0;
						return ;
					}
				}
				rule_tab[*last_r].dst_ip = stohi(found);
				break;

			case 6:
				if(num != 0){
					if(!isValidPrefixSize(num)){
						printk("Invalid IP address prefix size\n");
						*last_r = 0;
						return ;
					}
				}
				rule_tab[*last_r].dst_prefix_size = num;
				break;

			case 7:
				if(num != 0){
					if(!isValidMask(num)){
						printk("Invalid IP Subnet Mask\n");
						*last_r = 0;
						return ;
					}
				}
				rule_tab[*last_r].dst_prefix_mask = htonl(num);
				break;

			case 8:
				if(!isValidProtocol(num)){
					printk("Invalid protocol number: %d\n", num);
					*last_r = 0;
					return ;
				}
				rule_tab[*last_r].protocol = num;
				break;

			case 9:
				rule_tab[*last_r].src_port = htons(num);
				break;

			case 10:
				rule_tab[*last_r].dst_port = htons(num);
				break;

			case 11:
				rule_tab[*last_r].ack = num;
				if(!isValidAck(num)){
					printk("Invalid ack flag\n");
					*last_r = 0;
					return ;
				}
				break;

			case 12:
				rule_tab[*last_r].action = num;
				if(!isValidAction(num)){
					printk("Invalid action number\n");
					*last_r = 0;
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


void parse_rules(rule_t* rule_tab, char* data, int* last_r){
	char* found;//, line[100] = {0};
	int i=0;
	while( ((found = strsep(&data,"#")) != NULL) ){
		if(strlen(found) == 0)
			return;
		process_rule(rule_tab, found, last_r);
		if(i != 0){
			if(*last_r == 0){
				return ;
			}
		}	
		(*last_r)++;
		i++;
	}
	(*last_r)--;
}