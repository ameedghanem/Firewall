#ifndef _FW_H_
#define _FW_H_


// the protocols we will work with
typedef enum {
	PROT_ICMP	= 1,
	PROT_TCP	= 6,
	PROT_UDP	= 17,
	PROT_OTHER 	= 255,
	PROT_ANY	= 143,
} prot_t;


// various reasons to be registered in each log entry
typedef enum {
	REASON_FW_INACTIVE           = -1,
	REASON_NO_MATCHING_RULE      = -2,
	REASON_XMAS_PACKET           = -4,
	REASON_ILLEGAL_VALUE         = -6,
	REASON_NO_CONN_EXIST		 = -8,
	REASON_FOUND_CONN			 = -10,
	REASON_SYN_PACKET			 = -12,
	CONN_ALREADY_EXISTS			 = -14,
} reason_t;
	

// TCP FLAGS
#define TCP_FIN 0X01
#define TCP_SYN 0X02
#define TCP_RST 0X04
#define TCP_PSH 0X08
#define TCP_ACK 0X10
#define TCP_URG 0X20
#define TCP_ECE 0X40
#define TCP_CWR 0X80
#define TCP_NO_FLAG 0x00
#define TCP_SYN_ACK  (TCP_SYN | TCP_ACK)
#define TCP_RST_ACK  (TCP_RST | TCP_ACK)
#define TCP_FIN_ACK  (TCP_FIN | TCP_ACK)
#define TCP_ALL_FLAGS (TCP_FIN | TCP_SYN | TCP_RST | TCP_PSH | TCP_ACK | TCP_URG)


// auxiliary strings, for your convenience
#define DEVICE_NAME_RULES			"rules"
#define DEVICE_NAME_LOG				"fw_log"
#define DEVICE_NAME_CONNS			"conns"
#define DEVICE_NAME_RESET_LOG		"log"
#define DEVICE_NAME_FTP_PORT_CMD	"ftp_port_cmd"
#define FW_CHARDEV_NAME				"Firewll Device"
#define FW_CLASS					"fw"
#define LOOPBACK_NET_DEVICE_NAME	"lo"
#define IN_NET_DEVICE_NAME			"eth1"
#define OUT_NET_DEVICE_NAME			"eth2"

// auxiliary values, for your convenience
#define IP_VERSION		(4)
#define PORT_ANY		(0)
#define PORT_ABOVE_1023	(1023)
#define MAX_RULES		(50)

// auxilary string for the log table
#define RWI "REAOSN_FW_INACTIVE"
#define	RNMR "REASON_NO_MATCHING_RULE"
#define RXP "REASON_XMAS_PACKET"
#define RIV "REASON_ILLEGAL_VALUE"
#define ICMP "ICMP"
#define TCP "TCP"
#define UDP "UDP"
#define OTHER "OTHER"
#define ANY "any"
#define IN "in"
#define OUT "out"
#define ANY "any"
#define NO "no"
#define YES "yes"


//auxiliary IP Addresses
#define ETH1 			htonl(0x0a010101)
#define ETH2 			htonl(0x0a010202)
#define LO   			htonl(0x7f000001)
#define VLAN_1_IFACE	htonl(0x0a010103)
#define VLAN_2_IFACE	htonl(0x0a010203)


//auxiliary ports
#define HTTP_PORT 				80
#define FTP_CTRL_PORT 			21
#define FTP_DATA_PORT 			20
#define HTTP_PROXY_PORT 		800
#define FTP_CONTROL_PROXY_PORT	210
#define FTP_DATA_PROXY_PORT		209

// device minor numbers, for your convenience
typedef enum {
	MINOR_RULES    		= 0,
	MINOR_LOG      		= 1,
	MINOR_RESET	   		= 2,
	MINOR_CONNS    		= 3,
	MINOR_FTP_PORT_CMD	= 4,
} minor_t;

typedef enum {
	ACK_NO 		= 0x01,
	ACK_YES 	= 0x02,
	ACK_ANY 	= ACK_NO | ACK_YES,
} ack_t;

typedef enum {
	DIRECTION_IN 	= 0x01,
	DIRECTION_OUT 	= 0x02,
	DIRECTION_ANY 	= DIRECTION_IN | DIRECTION_OUT,
} direction_t;

// rule base
typedef struct {
	char rule_name[20];			// names will be no longer than 20 chars
	direction_t direction;
	__be32	src_ip;
	__be32	src_prefix_mask; 	// e.g., 255.255.255.0 as int in the local endianness
	__u8    src_prefix_size; 	// valid values: 0-32, e.g., /24 for the example above
								// (the field is redundant - easier to print)
	__be32	dst_ip;
	__be32	dst_prefix_mask; 	// as above
	__u8    dst_prefix_size; 	// as above	
	__be16	src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	__be16	dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023 
	__u8	protocol; 			// values from: prot_t
	ack_t	ack; 				// values from: ack_t
	__u8	action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_t;

// logging
typedef struct {
	unsigned long  	timestamp;     	// time of creation/update
	unsigned char  	protocol;     	// values from: prot_t
	unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
	__be32   		src_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be32			dst_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be16 			src_port;	  	// if you use this struct in userspace, change the type to unsigned short
	__be16 			dst_port;	  	// if you use this struct in userspace, change the type to unsigned short
	reason_t     	reason;       	// rule#index, or values from: reason_t
	unsigned int   	count;        	// counts this line's hits
} log_row_t;


typedef struct log_list_t{
    log_row_t* row;
    struct log_list_t* next;
} log_list_t;

#endif // _FW_H_