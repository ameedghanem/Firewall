import os,sys,re
import socket, struct
import logging

SHOW_LOG_PATH = "/dev/fw_log"
RESET_LOG_PATH = "/sys/class/fw/log/reset"
RULES_PATH = "/sys/class/fw/rules/rules"
CONNS_PATH = "/sys/class/fw/conns/conns"

PROT_ICMP = str(socket.htons(1))
PROT_TCP = str(socket.htons(6))
PROT_UDP = str(socket.htons(17))
PROT_OTHER = str(socket.htons(255))
PROT_ANY = str(socket.htons(143))

X0 = str(socket.htons(0))
X1 = str(socket.htons(1))
X2 = str(socket.htons(2))
X3 = str(socket.htons(3))

PORT_ABOVE_1023 = str(socket.htons(1023))
ANY = str(socket.htons(0))

BG_RED = '\033[41m'
BG_BLUE = '\033[46m'

RED = '\x1b[31m'#'\033[91m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
REG = '\x1b[0m'
NUM_OF_DASHES = 75
SEPARATOR = YELLOW + "-"*NUM_OF_DASHES + REG

####################################################
# Conifuring the log file the program will use.
####################################################

logging.basicConfig(
	level = logging.DEBUG,
	filename = '../.fwlog/main.log',
	format = '%(levelname).1s %(asctime)s %(message)s',
	datefmt = '%Y-%m-%d %H:%M:%S',
)
LOG = logging.getLogger()


#####################
# Auxilary functions.
#####################

def override_content(fpath1, fpath2):
	"""Accepts 2 file_paths: fpath1 and fpath2. It overrides the 1st file's content with the 2nd files's content."""
	data = ""
	with open(fpath2) as reader:
		data = reader.read()
	with open(fpath1, "w+") as writer:
		fpath1.write(data) #overriging file1 with files2's content.



def read(fpath):
	"""Accepts a file path , reads it and returns its ocntent"""
	with open(fpath) as reader:
		data = reader.read()
	return data



def validate_path(fpath):
	"""It terminate the program if the path does not exist."""
	ftype = "Module" if (fpath.startswith("/sys/class") or fpath.startswith('/dev/')) else "File"
	if not os.path.exists(fpath):
		errMSG =  RED + "Error: %s '%s' does not exist." % (ftype, fpath) + REG
		sys.exit(errMSG)


#######################################################################
# Encoding the rules table in order to help the firewall in reading it.
#######################################################################


def pack_direction(rule):
	"""Encodes the direcion into a prooper number according to the fw header file"""
	if rule[1] == "in":
		return "1"
	elif rule[1] == "out":
		return "2"
	elif rule[1] == "any":
		return "3"
	else:
		return "ERROR"

def pack_addr(rule, ind):
	"""Encodes the address,subnet mask,subnet prefix numbers according to the fw header file"""
	if rule[ind] == "any":
		return '$'.join(["0" for i in range(3)])
	else:
		try:
			lst = []
			prefix = int(rule[ind][rule[ind].index('/')+1:])
			lst.append(rule[ind][:rule[ind].index('/')])#str(struct.unpack("!I", socket.inet_aton(rule[ind][:rule[ind].index('/')]))[0]))
			lst.append(str(rule[ind][rule[ind].index('/')+1:]))
			lst.append(str((2**prefix-1) << (32-prefix)))
			return '$'.join(lst)
		except:
			return "ERROR" 

def pack_protocol(rule):
	"""Encodes the protocol into a prooper number according to the fw header file"""
	if rule[4] == "ICMP":
			return "1"
	elif rule[4] == "TCP":
		return "6"
	elif rule[4] == "UDP":
		return "17"
	elif rule[4] == "OTHER":
		return "255"
	elif rule[4] == "any":
		return "143"
	else:
		return "ERROR" 

def pack_port(rule, ind):
	"""Encodes the port number into a prooper number according to the fw header file"""
	port = rule[ind]
	try:
		if port == ">1023":
			return PORT_ABOVE_1023
		elif port == "any":
			return ANY
		elif 1 <= int(port) <= 1023:
			return str(socket.htons(int(port)))
	except:
		return "ERROR"

def pack_ack(rule):
	"""Encodes the ack flag into a prooper number according to the fw header file"""
	if rule[7] == "no":
		return "1"
	elif rule[7] == "yes":
		return "2"
	elif rule[7] == "any":
		return "3"
	else:
		return "ERROR"

def pack_answer(rule):
	"""Encodes the action into a prooper number according to the fw header file"""
	if rule[8] == "accept":
		return "1"
	elif rule[8] == "drop":
		return "0"
	else:
		return "ERROR"

def pack(rule):
	"""Encodes a single rule into a series of number according to the fw header file, and insert between each compoennt a $ sign"""
	packd_rule = ""
	rule_items = rule.split()
	t0 = rule_items[0]
	t1 = pack_direction(rule_items)
	t2 = pack_addr(rule_items, 2)
	t3 = pack_addr(rule_items, 3)
	t4 = pack_protocol(rule_items)
	t5 = pack_port(rule_items, 5)
	t6 = pack_port(rule_items, 6)
	t7 = pack_ack(rule_items)
	t8 = pack_answer(rule_items)
	packd_rule = t0+'$'+t1+'$'+t2+'$'+t3+'$'+t4+'$'+t5+'$'+t6+'$'+t7+'$'+t8
	return packd_rule


def pack_rules(rules):
	"""Encodes the whole rules"""
	i = 0
	lst_rules = rules.split('\n')
	if not "drop" in lst_rules[-1]:
		del(lst_rules[-1])
	packd_rules = []
	for rule in lst_rules:
		curr_rule = pack(rule)
		LOG.debug("packing rule num. %d" % i)
		i += 1
		if "ERROR" in curr_rule:
			return "ERORR"
		else:
			packd_rules.append(curr_rule)
	return '#'.join(packd_rules)



########################################################
# Decoding rules tables / log table into readable format
########################################################


def unpack_addr(row, ind):
	#print row
	#print ind
	s = socket.inet_ntoa(struct.pack("!I", int(row[ind])))
	slist = s.split('.')
	slist.reverse()
	return '.'.join(slist)


def unpack_protocol(row, ind):
	protocol = int(row[ind])
	if protocol == 1:
			return "ICMP"
	elif protocol == 6:
		return "TCP"
	elif protocol == 17:
		return "UDP"
	elif protocol == 255:
		return "OTHER"
	elif protocol == 143:
		return "any"


def unpack_port(row, ind):
	port = int(row[ind])
	if port == 1023:
		return ">1023"
	elif port == 0:
		return "any"
	elif 1 <= port < 1023:
		return str(port)



def unpack_answer(row, ind):
	if int(row[ind]) == 1:
		return "accept"
	elif int(row[ind]) == 0:
		return "drop"

def unpack_reason(row):
	if row[7] == "-1":
		return "REASON_FW_INACTIVE"
	if row[7] == "-2":
		return "REASON_NO_MATCHING_RULE"
	if row[7] == "-4":
		return "REASON_XMAS_PACKET"
	if row[7] == "-6":
		return "REASON_ILLEGAL_VALUE"
	if row[7] == "-8":
		return "REASON_NO_CONN_EXIST"
	if row[7] == "-10":
		return "REASON_FOUND_CONN"
	if row[7] == "-12":
		return "REASON_SYN_PACKET"
	if row[7] == "-14":
		return "CONN_ALREADY_EXISTS"
	#the reason is the rule number
	return row[7]
	

def unpack_row(row):
	lst = ["" for i in range(10)]
	if '\n' in row[0]:
		row[0] = row[0][:-1]
	lst[0] = row[0]
	lst[1] = unpack_addr(row, 1)
	lst[2] = unpack_addr(row, 2)
	lst[3] = row[3]
	lst[4] = row[4]
	lst[5] = unpack_protocol(row, 5)
	lst[6] = "0"
	lst[7] = unpack_answer(row, 6)
	lst[7] = RED + unpack_answer(row, 6) + REG if lst[7]=="drop" else '\033[34m' + unpack_answer(row, 6) + REG
	lst[8] = unpack_reason(row)
	lst[9] = row[8]
	return '{:<25}{:<18}{:<18}{:<12}{:<12}{:<10}{:<10}{:<19}{:<27}{:<20}'.format(*lst)


def unpack_ack(rule):
	if int(rule[9]) == 2:
		return "yes"
	elif int(rule[9]) == 1:
		return "no"
	else:
		return "any"


def unpack_addr_with_mask(rule, ind):
	if rule[ind] == "0" and rule[ind+1] == "0":
		return "any"
	unpacked_addr = ""
	unpacked_addr += unpack_addr(rule, ind) + '/'
	unpacked_addr += rule[ind+1]
	return unpacked_addr

def unpack_direction(rule):
	if int(rule[1]) == 1:
		return "in"
	elif int(rule[1]) == 2:
		return "out";
	elif int(rule[1]) == 3:
		return "any"


def unpack_rule(rule):
	if len(rule) != 11:
		return "ERR"
	lst = [0 for i in range(9)]
	t0 = rule[0]
	t1 = unpack_direction(rule)
	t2 = unpack_addr_with_mask(rule, 2)
	t3 = unpack_addr_with_mask(rule, 4)
	t4 = unpack_protocol(rule, 6)
	t5 = unpack_port(rule, 7)
	t6 = unpack_port(rule, 8)
	t7 = unpack_ack(rule)
	t8 = unpack_answer(rule, 10)
	lst[0] = t0
	lst[1] = t1
	lst[2] = t2
	lst[3] = t3
	lst[4] = t4
	lst[5] = t5
	lst[6] = t6
	lst[7] = t7
	lst[8] = t8
	return '{:<20}{:<13}{:<20}{:<20}{:<10}{:<13}{:<13}{:<10}{:<10}'.format(*lst)


def unpack_state(state):
	state_number = int(state)
	if state_number == 1:
		return "CLOSED"
	if state_number == 2:
		return "LISTEN"
	if state_number == 3:
		return "TCP_SYN_SENT"
	if state_number == 4:
		return "TCP_SYN_RECV"
	if state_number == 5:
		return "TCP_ESTABLISHED"
	if state_number == 6:
		return "TCP_CLOSE_WAIT"
	if state_number == 7:
		return "TCP_LAST ACK"
	if state_number == 8:
		return "TCP_FIN_WAIT_1"
	if state_number == 9:
		return "TCP_FIN_WAIT_2"
	if state_number == 10:
		return "TCP_FIN_CLOSING"
	if state_number == 11:
		return "TCP_TIME_WAIT"
		
	


def unpack_conn(conn):
	if conn[0] == '':
		del(conn[0])
	lst = [0 for i in range(5)]
	lst[0] = unpack_addr(conn, 0)
	lst[1] = conn[1]#unpack_port_v2(conn, 1)
	lst[2] = unpack_addr(conn, 2)
	lst[3] = conn[3]#unpack_port_v2(conn, 3)
	lst[4] = unpack_state(conn[4])
	return '{:<15}{:<12}{:<15}{:<12}{:<20}'.format(*lst)


def print_conns_table(conns_string):
	LOG.debug("printing the connection table: %s, len = %d" % (conns_string, len(conns_string)))
	if "no conns" in conns_string or conns_string == "":
		print(RED + "Connections Table is empty." + REG)
		return
	conns = conns_string.split('#')
	if '\n' in conns:
		conns.pop(conns.index('\n'))
	lst = ["src_ip", "src_port", "dst_ip", "dst_port", "state"]
	title = '{:<15}{:<12}{:<15}{:<12}{:<20}'.format(*lst)
	toprint = []
	toprint.append(title)
	toprint.append(SEPARATOR)
	for conn in conns:
		#print conn.split('*')
		curr_conn, reverse_curr_conn = conn.split('*')
		curr_conn, reverse_curr_conn = unpack_conn(curr_conn.split('$')), unpack_conn(reverse_curr_conn.split('$'))
		toprint.append(curr_conn)
		toprint.append(reverse_curr_conn)
		toprint.append(SEPARATOR)
	print('\n'.join(toprint))


def print_log(log):
	"""Printing the log of our firewall"""
	LOG.debug("printing the log")
	if log == "":
		print(RED + "Log File is empty." + REG)
		return 
	log_rows = log.split('#')
	#print log
	lst = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "hooknum", "action", "reason", "count"]
	title = '{:<25}{:<18}{:<18}{:<12}{:<12}{:<10}{:<10}{:<10}{:<27}{:<20}'.format(*lst)
	toprint = []
	toprint.append('-'*147)
	toprint.append(title)
	toprint.append('-'*147)
	for row in log_rows:
		if len(row) <= 2:
			continue
		#print row.split('$')
		unpacked_row = unpack_row(row.split('$'))
		#print 'x'
		toprint.append(unpacked_row)
	print('\n'.join(toprint))
		

def print_rules(rules):
	"""Print the rule table"""
	LOG.debug("printing the rule table")
	if "no rules" in rules:
		print(RED + "Rule Table isn't loaded yet." + REG)
		return 
	rows = rules.split('#')
	toprint = []
	title = ["rule name", "direction", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "ack", "action"]
	title = '{:<20}{:<13}{:<20}{:<20}{:<10}{:<13}{:<13}{:<10}{:<10}'.format(*title)
	toprint.append('-'*126)
	toprint.append(title)
	toprint.append('-'*126)
	for rule in rows:
		if rule =='\n':
			continue
		unpacked_rule = unpack_rule(rule.split('$'))
		toprint.append(unpacked_rule)
	toprint = '\n'.join(toprint)
	print(toprint)


def execute_command(argv):	
	if len(argv) == 2:
		cmd = argv[1]
		if cmd == "show_rules":
			validate_path(RULES_PATH)
			print_rules(read(RULES_PATH))
		elif cmd == "show_conns":
			validate_path(CONNS_PATH)
			print_conns_table(read(CONNS_PATH))
		elif cmd == "show_log":
			validate_path(SHOW_LOG_PATH)
			print_log(read(SHOW_LOG_PATH))
		elif cmd == "clear_log":
			validate_path(RESET_LOG_PATH)
			with open(RESET_LOG_PATH, "w+") as writer:
				writer.write("0")
			print(GREEN + "Clearing.." + REG)
		elif cmd == "--help" or cmd == "-h":
			sys.exit( YELLOW + "USAGE: python %s <command>" % argv[0] + REG)
		else:
			sys.exit(RED + "Error: Illegal Command" + REG)
	elif len(argv) == 3:
		cmd = argv[1]
		if cmd == "load_rules":
			validate_path(RULES_PATH)#validate that the rules device file exists!!
			validate_path(argv[2])#validate that the given file path exists
			rules = read(argv[2])
			rules = pack_rules(rules)
			if rules != "ERROR":#validate that the rules are valid
				with open(RULES_PATH, "wb") as writer:
					writer.write(rules)
		else:
			sys.exit(RED + "Error: Illegal Command" + REG)
	else:
		sys.exit(YELLOW + "USAGE: python %s <command>" % argv[0] + REG)	

def main(argv):
	execute_command(argv)

if __name__ == '__main__':
	LOG.debug("============== starting main ==============")
	main(sys.argv)