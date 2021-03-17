#ifndef _CONNS_TABLE_H_
#define _CONNS_TABLE_H_

#define CONN_LENGTH 50

typedef enum {
	TCP_STT_CLOSED 		= 	1, //states should never equal 0
	TCP_STT_LISTEN 		= 	2,
	TCP_STT_SYN_SENT 	=	3,
	TCP_STT_SYN_RECV 	= 	4,
	TCP_STT_ESTABLISHED = 	5,
	TCP_STT_CLOSE_WAIT 	= 	6,
	TCP_STT_LAST_ACK 	= 	7,
	TCP_STT_FIN_WAIT_1 	= 	8,
	TCP_STT_FIN_WAIT_2 	= 	9,
	TCP_STT_FIN_CLOSING = 	10,
	TCP_STT_TIME_WAIT 	= 	11,
	TCP_STT_ERROR		= 	-1, //this state indicates an error, i used it for testing the tcp state machine.
} TCP_STATE;



typedef struct connection_t{
	//unsigned long timestamp;//used for removing timeed out connections.
    __be32	src_ip;
    __be16	src_port;
    __be32	dst_ip;
    __be16	dst_port;
    TCP_STATE state;
    __be32	proxy_src_ip;
    __be16	proxy_src_port;
    __be32	proxy_dst_ip;
    __be16	proxy_dst_port;
    int isEstablished;
} connection_t;

typedef struct conns_table_t{
	unsigned long timestamp;
    connection_t* conn;
    connection_t* rconn;
    struct conns_table_t* next;
} conns_table_t;


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
 *finds a connection in the connection table
 */
conns_table_t* find_conn(conns_table_t* head, connection_t* conn);


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
 * the event paramter is actually the flag of the current packet in netfiler 
 * while the respnse flag specifies the flag the other side sent
 * 
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


//updates the state corresponding to the event-response 
TCP_STATE advance_state(TCP_STATE state, int event, int response);

//parses the connection table that is given by a string representation
void parse_conn(conns_table_t** conn_tab, char* data);

//updates the state of the given connection
int update_state(conns_table_t* conn, __be32 src_ip, int flag);

//checks if these parameters (src_ip, src_port, dst_ip, dst_port) represent a an existing connection in the connection table
//timestmp is given to update the timestamp of the given connection, if exists.
int check_conn(conns_table_t* conn_tab, __be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port, int flag, unsigned long timestamp);



#endif // _CONNS_TABLE_H_