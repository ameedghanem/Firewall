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
#include <net/tcp.h>
#include <linux/string.h>
#include "fw.h"
#include "conns_table.h"


ssize_t count_of_entries = 0;

int is_digit2(char c){
	return c <= '9' && c >= '0';
}

int compute_num2(char* num){
	int i, res = 0, factor=1;
	for(i=strlen(num)-1; i >= 0; i--){
		res += (num[i]-'0')*factor;
		factor *= 10;
	}
	return res;
}

int isNumber2(char* str){
	int i;
	for(i=0; i<strlen(str); i++){
		if(str[i] > '9' || str[i] < '0')
			return 0;
	}
	return 1;
}

unsigned int stohi2(char *ip){
	char c;
	unsigned int integer;
	int val;
	int i,j=0;
	integer=0;
	c = *ip;
	for (j=0;j<4;j++) {
		if (!is_digit2(c)){  //first char is 0
			return (0);
		}
		val=0;
		for (i=0;i<3;i++) {
			if (is_digit2(c)) {
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

int conn_exists(conns_table_t* conn1, connection_t* conn2){
	// conn
	int case1 = conn1->conn->src_ip == conn2->src_ip;
	int case2 = conn1->conn->src_port == conn2->src_port;
	int case3 = conn1->conn->dst_ip == conn2->dst_ip;
	int case4 = conn1->conn->dst_port == conn2->dst_port;
	//int case5 = conn1->conn->state == conn2->state;
	// rconn
	int case11 = conn1->rconn->src_ip == conn2->src_ip;
	int case22 = conn1->rconn->src_port == conn2->src_port;
	int case33 = conn1->rconn->dst_ip == conn2->dst_ip;
	int case44 = conn1->rconn->dst_port == conn2->dst_port;
	//int case55 = conn1->rconn->state == conn2->state;
	// Rr it equals to the rconn connecion either to the outgoing one
	return (case1 && case2 && case3 && case4) || (case11 && case22 && case33 && case44);
}


int is_conn_equals(connection_t* c1, connection_t* c2){
	int case1 = c1->src_ip == c2->src_ip && c1->src_port == c2->src_port;
	int case2 = c1->dst_ip == c2->dst_ip && c1->dst_port == c2->dst_port;
	return case1 && case2;
}

int is_proxy_conn_equals(connection_t* c1, connection_t* c2){
	int case1 = c1->proxy_src_ip == c2->proxy_src_ip;// && c1->proxy_src_port == c2->proxy_src_port;
	int case2 = c1->proxy_dst_ip == c2->proxy_dst_ip && c1->proxy_dst_port == c2->proxy_dst_port;
	return case1 && case2;
}

connection_t* find_conn_by_proxy(conns_table_t* head, connection_t* conn){
	if(head == NULL){
		return NULL;
	}
    else if(is_proxy_conn_equals(head->conn, conn) != -1)
    	return head->conn;
    else if(is_proxy_conn_equals(head->rconn, conn) != -1)
    	return head->rconn;
    else if(!head->next){//If it reached the end of our list and didnt find the wanted one, then it returns NULL
        return NULL;
    }
    return find_conn_by_proxy(head->next, conn);
}


conns_table_t* find_conn(conns_table_t* head, connection_t* conn){
	if(head == NULL){
		printk("head = null ?\n");
		return NULL;
	}
    if(conn_exists(head, conn)){
        return head;
    }
    if(!head->next){//If it reached the end of our list and didnt find the wanted one, then it returns NULL
        return NULL;
    }
    return find_conn(head->next, conn);
}


//rev_conn is the reverse connection of the connection conn
//I mean by reverse connection the connection with the reversed src,dst ip's/port's.
void set_conn_in_list(conns_table_t** conn_tab, connection_t* conn, connection_t* rev_conn, unsigned long timestamp){
	conns_table_t *new_conn = NULL, *temp = NULL, *head = NULL;
	if(conn == NULL || rev_conn == NULL){
		printk("what the f**k.\n");
		return;
	}
	new_conn = (conns_table_t*)kmalloc(sizeof(conns_table_t), GFP_ATOMIC);
	if(new_conn == NULL){
		printk("Failed to allocate a new conection.\n");
		return;
	}
	new_conn->conn = conn; new_conn->rconn = rev_conn; new_conn->timestamp = timestamp; new_conn->next = NULL;
	count_of_entries += 2; //modifying this variable to get the number of entries in the whole connections list
	if(*conn_tab == NULL){
		*conn_tab = new_conn;
		printk("well done\n");
		//kfree(new_conn); new_conn = NULL;
		return;
	}
	temp = find_conn(*conn_tab, conn);
	if(temp != NULL){
		//update_state(temp);
		//kfree(conn);
		kfree(rev_conn);
		kfree(new_conn);
		kfree(conn);
		count_of_entries -= 2;
		return;
	}
	head = *conn_tab;
	while(head != NULL)
		head = head->next; 
	head->next = new_conn;
}


//the ports who are set to 0 are ports that will be modifyed by the conn sysfS_device dynamically
void set_proxy_ports(connection_t* conn){
	if(conn->src_port == FTP_CTRL_PORT){
		conn->proxy_src_port = 0;
		conn->proxy_dst_port = conn->src_port;
	}else if(conn->dst_port == FTP_CTRL_PORT){
		conn->proxy_src_port = FTP_CONTROL_PROXY_PORT;
		conn->proxy_dst_port = conn->src_port;
	}else if(conn->src_port == FTP_DATA_PORT){
		conn->proxy_src_port = 0;
		conn->proxy_dst_port = conn->dst_port;
	}else if(conn->dst_port == FTP_DATA_PORT){
		conn->proxy_src_port = FTP_DATA_PROXY_PORT;
		conn->proxy_dst_port = conn->src_port;
	}else if(conn->src_port == HTTP_PORT){
		conn->proxy_src_port = 0;
		conn->proxy_dst_port = conn->src_port;
	}else if(conn->dst_port == HTTP_PORT){
		conn->proxy_src_port = HTTP_PROXY_PORT;
		conn->proxy_dst_port = conn->src_port;
	}
}


void set_proxy_conn(connection_t* conn){
	if(conn->src_ip == ETH1){
		conn->proxy_src_ip = VLAN_1_IFACE;
		conn->proxy_dst_ip = ETH1;
	}else if(conn->src_ip == ETH2){
		conn->proxy_src_ip = VLAN_2_IFACE;
		conn->proxy_dst_ip = ETH2;
	}
	set_proxy_ports(conn);
}


void add_conn(conns_table_t** conn_tab, __be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port, TCP_STATE state1, TCP_STATE state2, unsigned long timestamp){
	connection_t* new_conn = (connection_t*)kmalloc(sizeof(connection_t), GFP_ATOMIC);
	connection_t* rnew_conn = (connection_t*)kmalloc(sizeof(connection_t), GFP_ATOMIC);
	if(new_conn == NULL || rnew_conn == NULL){
		printk("In add_conn. Failed to allocate a new connection.\n");
		return;
	}
	new_conn->src_ip = src_ip;
	new_conn->dst_ip = dst_ip;
	new_conn->src_port = src_port;
	new_conn->dst_port = dst_port;
	new_conn->state = state1;
	//===========================
	rnew_conn->src_ip = dst_ip;
	rnew_conn->dst_ip = src_ip;
	rnew_conn->src_port = dst_port;
	rnew_conn->dst_port = src_port;
	rnew_conn->state = state2;
	//==========================
	set_proxy_conn(new_conn);
	set_proxy_conn(rnew_conn);
	//==========================
	set_conn_in_list(conn_tab, new_conn, rnew_conn, timestamp);
	printk("done adding connection: %d\n", (new_conn->src_ip == rnew_conn->dst_ip) && (new_conn->dst_ip == rnew_conn->src_ip) && (new_conn->src_port == rnew_conn->dst_port) && (new_conn->dst_port == rnew_conn->src_port));
}

void freeConns(conns_table_t* head){
    if(head != NULL){
        freeConns(head->next);
        kfree(head->conn);
        kfree(head->rconn);
        kfree(head);
    }
    head = NULL;
}


int conns_length(conns_table_t* head){
	return count_of_entries * CONN_LENGTH;
}


char* encode_conns(conns_table_t* head){
	int len;
	char src_ipS[10], src_portS[10], dst_ipS[10], dst_portS[10], stateS[10], src_ipSR[10], src_portSR[10], dst_ipSR[10], dst_portSR[10], stateSR[10];
	char* conns_str;
	conns_table_t* phead = head;
	conns_str = NULL;
	len = conns_length(head);
	if(len == 0){		
		return "";
	}
	conns_str = kcalloc(len, sizeof(char), GFP_ATOMIC);
	if(conns_str == NULL)
		return NULL;
	memset(conns_str, '\0', len);
	while(phead != NULL){
		sprintf(src_ipS, "%d", phead->conn->src_ip);
		sprintf(src_portS, "%d", phead->conn->src_port);
		sprintf(dst_ipS, "%d", phead->conn->dst_ip);
		sprintf(dst_portS, "%d", phead->conn->dst_port);
		sprintf(stateS, "%d", phead->conn->state);
		//==============================================
		sprintf(src_ipSR, "%d", phead->rconn->src_ip);
		sprintf(src_portSR, "%d", phead->rconn->src_port);
		sprintf(dst_ipSR, "%d", phead->rconn->dst_ip);
		sprintf(dst_portSR, "%d", phead->rconn->dst_port);
		sprintf(stateSR, "%d", phead->rconn->state);
		//===============================================
		strcat(conns_str, src_ipS);
		strcat(conns_str, "$");
		strcat(conns_str, src_portS);
		strcat(conns_str, "$");
		strcat(conns_str, dst_ipS);
		strcat(conns_str, "$");	
		strcat(conns_str, dst_portS);
		strcat(conns_str, "$");
		strcat(conns_str, stateS);
		strcat(conns_str, "*");
		strcat(conns_str, src_ipSR);
		strcat(conns_str, "$");
		strcat(conns_str, src_portSR);
		strcat(conns_str, "$");
		strcat(conns_str, dst_ipSR);
		strcat(conns_str, "$");
		strcat(conns_str, dst_portSR);
		strcat(conns_str, "$");
		strcat(conns_str, stateSR);
		strcat(conns_str, "#");
		phead = phead->next;
	}
	return conns_str;
}

/*
 *changes the packet src_ip/src_port if toChangeSrc != 0, else, it changes the dst_ip/dst_port
 */
void change_src_ip(struct sk_buff *skb, __be32 proxy_ip, __be16 proxy_port, int toChangeSrc){
	struct iphdr *iph;
	struct tcphdr *tcph;
	int tcplen;
	if(skb_is_nonlinear(skb)){//if skb is non linear, it will cause a failure in resulted checksum as i checked out by wireshark
		if(skb_linearize(skb) != 0){
			printk("failed to liearize\n");
			return;
		}
	}
	iph = ip_hdr(skb);
	if(!iph)
		return;
	tcph = (struct tcphdr *)(skb->data + (iph->ihl << 2));
	if(!tcph)
		return;
	if(toChangeSrc == 1){
		iph->saddr = proxy_ip;
		tcph->source = htons(proxy_port);
		tcplen = (skb->len - ((iph->ihl) << 2));
		tcph->check = 0;		
		tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial((char*)tcph, tcplen, 0));
		skb->ip_summed = CHECKSUM_NONE; //stop offloading
		iph->check = 0;
		iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
		return;
	}
	iph->daddr = proxy_ip;
	tcph->dest = htons(proxy_port);
	tcplen = (skb->len - ((iph->ihl) << 2));
	tcph->check = 0;		
	tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial((char*)tcph, tcplen, 0));
	skb->ip_summed = CHECKSUM_NONE; //stop offloading
	iph->check = 0;
	iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
	return;
}


//==================================
// TCP FINITE STATE MACHINE HANDLERS
//==================================
TCP_STATE handle_closed(int event, int response){
	if(event == TCP_SYN && response == 0)
		return TCP_STT_SYN_SENT;
	if((event == TCP_ACK && response == 0) || (event == 0 && response == TCP_ACK))
		return TCP_STT_CLOSED;
	if((event == TCP_RST_ACK && response == 0) || (event == 0 && response == TCP_RST_ACK))
		return TCP_STT_CLOSED;
	return TCP_STT_ERROR;
}

TCP_STATE handle_listen(int event, int response){
	if((event == TCP_SYN_ACK && response == 0) || (event == 0 &&  response == TCP_SYN))
		return TCP_STT_SYN_RECV;
	if((event == TCP_RST_ACK && response == 0) || (event == 0 &&  response == TCP_RST_ACK))
		return TCP_STT_CLOSED;
	if((event == TCP_RST && response == 0) || (event == 0 &&  response == TCP_RST))
		return TCP_STT_CLOSED;
	return TCP_STT_ERROR;
}

TCP_STATE handle_syn_sent(int event, int response){
	if((event == TCP_SYN_ACK && response == 0 ) || (event == 0 && response == TCP_SYN))
		return TCP_STT_SYN_RECV;
	if((event == TCP_ACK && response == 0) || (event == 0 && response == TCP_SYN_ACK))
		return TCP_STT_ESTABLISHED;
	if((event == TCP_RST && response == 0 ) || (event == 0 && response == TCP_RST))
		return TCP_STT_CLOSED;
	if((event == TCP_RST_ACK && response == 0 ) || (event == 0 && response == TCP_RST_ACK))
		return TCP_STT_CLOSED;
	return TCP_STT_ERROR;
}

TCP_STATE handle_syn_recv(int event, int response){
	if(event == TCP_FIN && response == 0)
		return TCP_STT_FIN_WAIT_1;
	else if(event == 0 && response == TCP_ACK)
		return TCP_STT_ESTABLISHED;
	if((event == TCP_RST && response == 0 ) || (event == 0 && response == TCP_RST))
		return TCP_STT_CLOSED;
	if((event == TCP_RST_ACK && response == 0 ) || (event == 0 && response == TCP_RST_ACK))
		return TCP_STT_CLOSED;
	return TCP_STT_ERROR;
}

TCP_STATE handle_established(int event, int response){
	if((event == TCP_FIN && response == 0) || (event == TCP_FIN_ACK && response == 0))
		return TCP_STT_FIN_WAIT_1;
	else if((event == 0 && response == TCP_FIN) || (event == 0 && response == TCP_FIN_ACK))
		return TCP_STT_CLOSE_WAIT;
	else if((event == TCP_ACK && response == 0) || (event == 0 && response == TCP_ACK))
		return TCP_STT_ESTABLISHED;
	else if((event == TCP_RST && response == 0) || (event == 0 && response == TCP_RST))
		return TCP_STT_CLOSED;
	else if((event == TCP_RST_ACK && response == 0) || (event == 0 && response == TCP_RST_ACK))
		return TCP_STT_CLOSED;
	return TCP_STT_ERROR;
}

TCP_STATE handle_close_wait(int event, int response){
	if((event == TCP_FIN && response == 0) || (event == TCP_FIN_ACK && response == 0))
		return TCP_STT_LAST_ACK;
	else if((event == TCP_RST && response == 0) || (event == 0 && response == TCP_RST))
		return TCP_STT_CLOSED;
	else if((event == TCP_RST_ACK && response == 0) || (event == 0 && response == TCP_RST_ACK))
		return TCP_STT_CLOSED;
	return TCP_STT_ERROR;
}

TCP_STATE handle_last_ack(int event, int response){
	if((event == 0 && response == TCP_ACK))
		return TCP_STT_CLOSED; //FIN_WAIT_2;
	else if((event == TCP_RST && response == 0) || (event == 0 && response == TCP_RST))
		return TCP_STT_CLOSED;
	else if((event == TCP_RST_ACK && response == 0) || (event == 0 && response == TCP_RST_ACK))
		return TCP_STT_CLOSED;
	return TCP_STT_ERROR;
}

TCP_STATE handle_fin_wait_1(int event, int response){
	if((event == 0 && response == TCP_ACK) || (event == 0 && response == TCP_FIN_ACK))
		return TCP_STT_FIN_WAIT_2;
	else if(event == TCP_ACK && event == 0)
		return TCP_STT_FIN_CLOSING;
	else if(event == 0 && event == TCP_FIN)
		return TCP_STT_CLOSED;
	else if((event == TCP_RST && response == 0) || (event == 0 && response == TCP_RST))
		return TCP_STT_CLOSED;
	else if((event == TCP_RST_ACK && response == 0) || (event == 0 && response == TCP_RST_ACK))
		return TCP_STT_CLOSED;
	return TCP_STT_ERROR;
}

TCP_STATE handle_fin_wait_2(int event, int response){
	if((event == TCP_ACK && response == 0) || (event == 0 && response == TCP_FIN_ACK) || (event == 0 && response == TCP_FIN))
		return TCP_STT_CLOSED;
	else if((event == TCP_RST && response == 0) || (event == 0 && response == TCP_RST))
		return TCP_STT_CLOSED;
	else if((event == TCP_RST_ACK && response == 0) || (event == 0 && response == TCP_RST_ACK))
		return TCP_STT_CLOSED;
	return TCP_STT_ERROR;
}

TCP_STATE handle_fin_closing(int event, int response){
	if((event == 0 && response == TCP_ACK))
		return TCP_STT_CLOSED;
	else if((event == TCP_RST && response == 0) || (event == 0 && response == TCP_RST))
		return TCP_STT_CLOSED;
	else if((event == TCP_RST_ACK && response == 0) || (event == 0 && response == TCP_RST_ACK))
		return TCP_STT_CLOSED;
	return TCP_STT_ERROR;
}

TCP_STATE handle_time_wait(int event, int response){
	if((event == TCP_RST && response == 0) || (event == 0 && response == TCP_RST))
		return TCP_STT_CLOSED;
	else if((event == TCP_RST_ACK && response == 0) || (event == 0 && response == TCP_RST_ACK))
		return TCP_STT_CLOSED;
	return TCP_STT_ERROR;
}


//=============================================
// TCP FINITE STATE MACHINE TRANSITION FUNCTION
//=============================================
TCP_STATE advance_state(TCP_STATE state, int event, int response){
	switch(state){
		case TCP_STT_CLOSED:
			return handle_closed(event, response);

		case TCP_STT_LISTEN:
			return handle_listen(event, response);

		case TCP_STT_SYN_SENT:
			return handle_syn_sent(event, response);

		case TCP_STT_SYN_RECV:
			return handle_syn_recv(event, response);

		case TCP_STT_ESTABLISHED:
			return handle_established(event, response);

		case TCP_STT_CLOSE_WAIT:
			return handle_close_wait(event, response);

		case TCP_STT_LAST_ACK:
			return handle_last_ack(event, response);

		case TCP_STT_FIN_WAIT_1:
			return handle_fin_wait_1(event, response);

		case TCP_STT_FIN_WAIT_2:
			return handle_fin_wait_2(event, response);

		case TCP_STT_FIN_CLOSING:
			return handle_fin_closing(event, response);

		case TCP_STT_TIME_WAIT:
			return handle_time_wait(event, response);

		default:
			return TCP_STT_ERROR;
	}
	return TCP_STT_CLOSED;//should never reach this line
}


int modify_proxy_conn(conns_table_t** conn_tab, __be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port, __be16 proxy_port){
	connection_t conn;
	conns_table_t* found = NULL;
	conn.src_ip = src_ip; conn.src_ip = src_port;
	conn.src_ip = dst_ip; conn.src_ip = dst_port;
	found = find_conn(*conn_tab, &conn);
	if(!found){
		printk("Didn't find a proper proxy connection.\n");
		return -1;
	}
	found->conn->proxy_src_port = proxy_port;
	return 1;
}


void parse_conn(conns_table_t** conn_tab, char* data){
	int i=0, num;
	char* found;
	__be32 src_ip, dst_ip;
	__be16 src_port, dst_port, proxy_port;
	TCP_STATE conn_state1, conn_state2;
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

			case 4:
				proxy_port = num;
				break;

			default:
				//{}
			i++;
		}
	}
	//adding the connection to the connection table
	//add_conn(conn_tab, src_ip, src_port, dst_ip, dst_port, conn_state1, conn_state2, 0);
	if(!modify_proxy_conn(conn_tab, src_ip, src_port, dst_ip, dst_port, proxy_port)){
		printk("Didnt' find a proper proxy conn.\n");
	}
}

int update_state(conns_table_t* conn, __be32 src_ip, int flag){
	TCP_STATE curr_conn_state, curr_rconn_state;
	/*if(conn == NULL){
		printk("update state: connection table is NULL\n");
		return;
	}*/
	if(conn == NULL){
		printk(" [][][][][][][][][][][][][][][][][][][][][][][][][][][][[][[[][]\n");
		printk("conetction table is empty\n");
		printk(" [][][][][][][][][][][][][][][][][][][][][][][][][][][][[][[[][]\n");
		return 0;
	}
	curr_conn_state = conn->conn->state; curr_rconn_state = conn->rconn->state; 
	if(conn->conn->src_ip == src_ip){
		conn->conn->state = advance_state(conn->conn->state, flag, 0) != TCP_STT_ERROR ? advance_state(conn->conn->state, flag, 0): curr_conn_state;
		conn->rconn->state = advance_state(conn->rconn->state, 0, flag) != TCP_STT_ERROR ? advance_state(conn->rconn->state, 0, flag): curr_rconn_state;
	}else if(conn->rconn->src_ip == src_ip){
		conn->rconn->state = advance_state(conn->rconn->state, flag, 0) != TCP_STT_ERROR ? advance_state(conn->rconn->state, flag, 0): curr_rconn_state;
		conn->conn->state = advance_state(conn->conn->state, 0, flag) != TCP_STT_ERROR ? advance_state(conn->conn->state, 0, flag): curr_conn_state;
	}
	return (conn->conn->state != TCP_STT_ERROR) && (conn->rconn->state != TCP_STT_ERROR);
}


int check_conn(conns_table_t* conn_tab, __be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port, int flag, unsigned long timestamp){
	connection_t temp_conn;
	conns_table_t* conn;

	temp_conn.src_ip = src_ip; temp_conn.dst_ip = dst_ip; 
	temp_conn.src_port = src_port; temp_conn.dst_port = dst_port;

	conn = find_conn(conn_tab, &temp_conn);
	if(conn == NULL){
		printk("found_conn returned zero\n");
		return 0;
	}
	if(!update_state(conn, src_ip, flag))
		return 0;
	conn->timestamp = timestamp;
	if(conn->conn->state == TCP_STT_ESTABLISHED && conn->rconn->state == TCP_STT_ESTABLISHED){
		conn->conn->isEstablished = 1;
		conn->rconn->isEstablished = 1;
	}
	return 1;
}



