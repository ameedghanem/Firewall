#ifndef _RULES_PARSER_H_
#define _RULES_PARSER_H_

#include "fw.h"

/*
 * @param port is the given packet's port
 * @param rule_port is the current rule's port in the rules table
 * It returns 1 iff port is valid port according the rule port
 */
int isValidPort( __be16 port, __be16 rule_port);


/*
 * @param protocol
 * It returns 1 iff protocol is one these five Enums:
 * TCP, UDP, ICMP, ANY, OTHER
 */
int isValidProtocol(prot_t protocol);


/*
 * @param action
 * returns 1 iff action is a valid enum value
 */
int isValidAction(int action);


/*
 * @param direct
 * returns 1 iff direct is  valid direction enum value
 */
int isValidDirection(direction_t direct);


/*
 * @param a
 * It returns 1 iff a is valid ack enum value
 */
int isValidAck(ack_t a);


/*
 * @param x
 * returns 1 iff x is a valid subnet mask
 */
int isValidMask(int x);


/*
 * @param x
 * returns 1 iff x is a valid prefix size
 */
int isValidPrefixSize(int x);


/*
 * @param r1 is a specific rules that is currently compared to
 * @param r2 is a rule_t that contains the data of the current packet
 * It returns 1 iff r2 is validated against r2
 */
int rule_equal(rule_t* r1, rule_t* r2);



/*
 * @param rule
 * return 1 iff rule is a valid rule
 */
void check_rule(rule_t* rule_tab, rule_t* rule, int* last_r, char* action_and_reason);


/*
 * @param str
 * resets a string by filling it with '\0'
 */
void reset_string(char* str);


/*
 * It packs the rule components into a string and store it in the rule str param
 */
void pack_rule(char* rule_str, char* rulename, char* direction, char* src_ip, char* src_prefix, char* dst_ip, char* dst_prefix,
					 char* protocol, char* src_port, char* dst_port, char* ack, char* action);



/*
 * @param str
 * checks whether str represents a number or not
 */
int isNumber(char* str);


/*
 * @param num
 * computes the number that the param num represent, if does not represent a number it returns 0
 */
int compute_num(char* num);


/*
 * @param rule
 * encodes a rule into a string and returns it
 */
void rule_to_str(rule_t* rule, char* rule_Str, int* last_r);


/*
 * @param rule_tab
 * It packs the rule tabe into a string
 */
void ruleTable_to_str(rule_t* rule_tab, char* rule_str, int* last_r);


/*
 * checks whether the charecter c is a digit or not
 */
int isdigit(char c);



/*
 * converts an ip address into unsigned int
 */
unsigned int stohi(char *ip);



/*
 * @param rules_tab
 * @param last_r
 * It resets the rule table
 */
void reset_rules(rule_t* rules_tab, int* last_r);


/*
 * @param data
 * It parses the given data into a rule and modifyes the rule table
 */
void process_rule(rule_t* rule_tab, char* data, int* last_r);


/*
 * @param data
 * It parses the whole rule table
 */
void parse_rules(rule_t* rule_tab, char* data, int* last_r);


#endif // _RULES_PARSER_H_