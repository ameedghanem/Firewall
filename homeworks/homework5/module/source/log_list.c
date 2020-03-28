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
#include "../includes/log_list.h"


int log_equals(log_row_t* r1, log_row_t* r2){
	return r1->protocol==r2->protocol && r1->action==r2->action && r1->src_ip==r2->src_ip && r1->dst_ip==r2->dst_ip && r1->src_port==r2->src_port && r1->dst_port==r2->dst_port && r1->reason==r2->reason;
}


log_list_t* find_node(log_list_t* head, log_row_t* row){
	if(head == NULL){
		return NULL;
	}
    if(log_equals(head->row, row)){
        return head;
    }
    if(!head->next){
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


void set_row_in_list(log_list_t** log_tab, log_row_t* row){
	//printk("int set row\n");
	log_list_t *node, *head;
	log_list_t* new_node = NULL;
	head = *log_tab;
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
        *log_tab = new_node;
        return;
    }
    //reach the last node and set it's next node to be the new node.
    while(head->next != NULL)
    	head = head->next;
    head->next = new_node;
    //printList();
}


void add_row(log_list_t** log_tab, unsigned long timestamp, unsigned char protocol, unsigned char action, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, reason_t reason){
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
	set_row_in_list(log_tab, new_row);
}


void freeList(log_list_t* head){
    //if(head != NULL){
	if(list_length(head) != 0){
        freeList(head->next);
        kfree(head->row);
        kfree(head);
    }
    head = NULL;
}


int count_of_entries(log_list_t* head){
	if(head == NULL)
		return 0;
	return 1 +  count_of_entries(head->next);
}


int list_length(log_list_t* head){
	return count_of_entries(head)*MAX_ROW_LENGTH;
}

//char* logSTR = NULL;

char* log2str(log_list_t* head){
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
	printk(" -> %s\n", logSTR);
	return logSTR;

}