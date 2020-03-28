#ifndef _CONNS_TABLE_H_
#define _CONNS_TABLE_H_

#include "fw.h"


int isdigit2(char c);

/*
 *computes the num that is represented in the string 'num'. if it does not represent a number it returns then 0.
 */
int compute_num2(char* num);


/*
 *returns 1 iff str is a valid number (an char array of didgits)
 */
int isNumber2(char* str);


/*
 *converts ip address into a number
 */
unsigned int stohi2(char *ip);



/*
 *checks if conn2 exists in the connection table conn1
 */
int conn_exists(conns_table_t* conn1, connection_t* conn2);


/*
 *compares between two connections
 */
int is_conn_equals(connection_t* c1, connection_t* c2);


/*
 *compares between two proxy connections
 */
int is_proxy_conn_equals(connection_t* c1, connection_t* c2);


/*
 *finds a connection by comparing proxy connections
 */
connection_t* find_conn_by_proxy(conns_table_t* head, connection_t* conn);


/*
 *finds a connection by comparing dst end points
 */
connection_t* find_conn_by_dst(conns_table_t* head, connection_t* conn);


/*
 *finds a connection in the connection table
 */
conns_table_t* find_conn(conns_table_t* head, connection_t* conn);


/*
 *finds a connection in the connection table, returns the specific connection, not the entry that contains both
 */
connection_t* find_one_conn(conns_table_t* head, connection_t* conn);


/*
 *set a new connection in the connection table
 */
void set_conn_in_list(conns_table_t** conn_tab, connection_t* conn, connection_t* rev_conn, unsigned long timestamp);


/*
 *sets proxy ports for proxy connection for the given connection
 */
void set_proxy_ports(connection_t* conn);


/*
 *sets a proxy connection for the given connection
 */
void set_proxy_conn(connection_t* conn);


/*
 *modifyes the proxy connection by setting the proxy src port which is calcuted from the packet in the local out hook !
 */
int modify_proxy_conn(conns_table_t** conn_tab, __be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port, __be16 proxy_port);


/*
 *adds a new connection to the connection table
 */
void add_conn(conns_table_t** conn_tab, __be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port, TCP_STATE state1, TCP_STATE state2, unsigned long timestamp);


/*
 *frees the connection table
 */
void freeConns(conns_table_t* head);


/*
 *returns the number fo entries in head
 */
int num_of_entries(conns_table_t* head);


/*
 *returns the conection table length
 */
int conns_length(conns_table_t* head);


/*
 *encode the connection table into a string and retrurn the resulting string
 * this functions will be used ofc when for conns sysfs show implementaion
 */
char* encode_conns(conns_table_t* head);


/*
 *change the ip address and the port number
 * if toChaneSrc == 1 then it changes the src ip/port
 * if it's 0 then it changes the dst ip/port
 */
void change_src_ip(struct sk_buff *skb, __be32 proxy_ip, __be16 proxy_port, int toChangeSrc);


//============================
//	TCP_STATE_MACHINE HANDLERS
//============================
/*
 * @param event: the flag of the current packet
 * @param response: the flag that the other side sent
 * each hacndler returns a tcp state enum 
 */

TCP_STATE handle_closed(int event, int response);

TCP_STATE handle_listen(int event, int response);

TCP_STATE handle_syn_sent(int event, int response);

TCP_STATE handle_syn_recv(int event, int response);

TCP_STATE handle_established(int event, int response);

TCP_STATE handle_close_wait(int event, int response);

TCP_STATE handle_last_ack(int event, int response);

TCP_STATE handle_fin_wait_1(int event, int response);

TCP_STATE handle_fin_wait_2(int event, int response);

TCP_STATE handle_fin_closing(int event, int response);

TCP_STATE handle_time_wait(int event, int response);


/*
 * @params: event, reponse
 * updates the state corresponding to the event-response 
 */
TCP_STATE advance_state(TCP_STATE state, int event, int response);


/*
 * parses the connection table that is given by a string representation
 */
void parse_conn(conns_table_t** conn_tab, char* data);


/*
 * updates the state of the given connection
 */
int update_state(conns_table_t* conn, __be32 src_ip, int flag);


/*checks if these parameters (src_ip, src_port, dst_ip, dst_port) represent a an existing connection in the connection table
 *timestmp is given to update the timestamp of the given connection, if exists.
 */
int check_conn(conns_table_t* conn_tab, __be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port, int flag, unsigned long timestamp);


/*
 * @param conn_tab: a reference for the connection table
 * @param timestamp: the moment the packet arrvied
 * Either it removes connections that timed out or closed ones
 */
void remove_closed_and_timed_out_conns(conns_table_t** conn_tab, unsigned long timestamp);


/*
 * extracts the flag of the given tcp packet and returns it
 */
int get_flag(struct tcphdr* tcph);



#endif // _CONNS_TABLE_H_