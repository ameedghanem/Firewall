#ifndef _LOG_LIST_H_
#define _LOG_LIST_H_

#include "fw.h"

/*
 * @param r1
 * @param r2
 * returns 1 iff r1 is a log row of the same packet of r2
 */
int log_equals(log_row_t* r1, log_row_t* r2);


/*
 * @param head: log list
 * @param row: a log row
 * returns 1 iff head contains row
 */
log_list_t* find_node(log_list_t* head, log_row_t* row);


/*
 * @param head: log list
 * @param row: a log row
 * adds row to the log list head
 */
void set_row_in_list(log_list_t** log_tab, log_row_t* row);


/*
 * It packs the log_row components into a row and calls set_row_in_list
 */
void add_row(log_list_t** log_tab, unsigned long timestamp, unsigned char protocol, unsigned char action, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, reason_t reason);


/* 
 * @param head: the log list head
 * frees the log list
 */
void freeList(log_list_t* head);


/*
 * @param head: represents the log list
 * return the number of entries that log list contains
 */
int count_of_entries(log_list_t* head);


/*
 * @param head: the log list
 * returns the log list length
 */
int list_length(log_list_t* head);


/*
 * @parm log_str: a referense to the log string
 * @param head: the log list
 * packs the log list into a string
 */
char* log2str(log_list_t* head);


#endif // _LOG_LIST_H_