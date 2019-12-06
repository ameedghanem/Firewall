import os,sys,re
import socket, struct

SHOW_LOG_PATH = "/dev/fw_log"
RESET_LOG_PATH = "/sys/class/fw/log/reset" #well, reset is the attribute, so in the driver i simply validate whether it equals 0 or not, if it does then i do clear the logs.
RULES_PATH = "/sys/class/fw/rules/rules"

def override_content(fpath1, fpath2):
	"""Accepts 2 file_paths: fpath1 and fpath2.It overrides the 1st file's content with the 2ns files's content."""
	data = ""
	with open(fpath2) as reader:
		data = reader.read()
	with open(fpath1, "w+") as writer:
		fpath1.write(data) #overriging file1 with files2's content.



def read(fpath):
	"""Accepts a file path , reads it and returns its ocntent"""
	data = ""
	with open(RULES_PATH) as reader:
		data = reader.read()
	return data



def validate_path(fpath):
	"""It terminate the program if the path does not exist."""
	if not os.path.exists(fpath):
		sys.exit("The File %s doesn't exist." % fpath)



def parse_direction(rule):
	if rule[1] == "in":
		return "1"
	elif rule[1] == "out":
		return "2"
	elif rule[1] == "any":
		return "3"
	else:
		return "ERROR"

def parse_addr(rule, ind):
	if rule[ind] == "any":
		return '$'.join(["1" for i in range(3)])
	else:
		try:
			lst = []
			lst.append(str(struct.unpack("!I", socket.inet_aton(rule[ind][:rule[ind].index('/')]))[0]))
			lst.append(str(rule[ind][rule[ind].index('/')+1:]))
			lst.append(str((2**prefix-1) << (32-prefix)))
			return '$'.join(lst)
		except:
			return "ERROR" 

def parse_protocol(rule):
	if rule[4] == "ICMP":
			return "1"
	elif rule[4] == "TCP":
		return "6"
	elif rule[4] == "UDP":
		return "17"
	elif rule[4] == "OTHER":
		return "255"
	elif rule[4] == "ANY":
		return "143"
	else:
		return "ERROR" 

def parse_port(rule, ind):
	port = rule[ind]
	try:
		if port == ">1023":
			return "1023"
		elif port == "0":
			return "0"
		elif 1 <= int(port) <= 1023:
			return port
	except:
		return "ERROR"

def parse_ack(rule):
	if rule[7] == "no":
		return "1"
	elif rule[7] == "yes":
		return "2"
	elif rule[7] == "any":
		return "3"
	else:
		return "ERROR"

def parse_answer(rule):
	if rule[8] == "accept":
		return "1"
	elif rule[8] == "drop":
		return "0"
	else:
		return "ERROR"

def parse(rule):
	parsed_rule = ""
	rules_itmes = rule.split()
	parsed_rule += parse_direction(rule_items)+'$'
	parsed_rule += parse_addr(rule_items, 2)+'$'
	parsed_rule += parse_addr(rule_items, 3)+'$'
	parsed_rule += parse_protocl(rule_items)+'$'
	parsed_rule += parse_port(rule_items, 5)+'$'
	parsed_rule += parse_port(rule_items, 6)+'$'
	parsed_rule += parse_ack(rule_items)+'$'
	parsed_rule += parse_answer(rule_items)
	return parsed_rule


def parse_rules(rules):
	lst_rules = rules.split('\n')
	parsed_rules = []
	for rule in lst_rules:
		curr_rule = parse(rule)
		if "ERROR" in curr_rule:
			return "ERORR"
		else:
			parsed_rules.append(curr_rule)
	return '#'.join(parsed_rules)



def unpack_addr(row, ind):
	return socket.inet_ntoa(struct.pack("!I", row[ind]))


def unpack_protocol(row, ind):
	if row[ind] == "1":
			return "ICMP"
	elif row[ind] == "6":
		return "TCP"
	elif row[ind] == "17":
		return "UDP"
	elif row[ind] == "255":
		return "OTHER"
	elif row[ind] == "143":
		return "ANY"


def unpack_port(row, ind):
	port = row[ind]
	if port == "1023":
		return ">1023"
	elif port == "0":
		return "0"
	elif 1 <= int(port) <= 1023:
		return port



def unpack_answer(row, ind):
	if row[ind] == "1":
		return "accept"
	elif row[ind] == "0":
		return "drop"

def unpack_reason(row):
	if row[8] == "-1":
		return "REASON_FW_INACTIVE"
	if row[8] == "-2":
		return "REASON_NO_MATCHING_RULE"
	if row[8] == "-4":
		return "REASON_XMAS_PACKET"
	if row[8] == "-6":
		return "REASON_ILLEGAL_VALUE"


"""def unpack_timestamp(row):
	pkt_time = long(row[0])
	seconds = pkt_time%60;
	pkt_time /= 60;
	minutes = pkt_time%60;
	pkt_time /= 60;
	hours = pkt_time%24;
	timestamp = "%d:%d:%d" % (hours, minutes, seconds)
	return timestamp"""


def unpack_row(row):
	unpacked_row = ""
	unpacked_row += unpack_timestamp(row) + '\t'*4
	unpacked_row += unpack_addr(row, 1) + '\t'*4
	unpacked_row += unpack_addr(row, 2) + '\t'*4
	unpacked_row += unpack_port(row, 3) + '\t'*4
	unpacked_row += unpack_port(row, 4) + '\t'*4
	unpacked_row += unpack_protocol(row, 5) + '\t'*4
	unpacked_row += "2" + '\t'*4 #hooknum is allways 4 which is the forward hook point.
	unpacked_row += unpack_answer(row, 7) + '\t'*4
	unpacked_row += unpack_reason(row) + '\t'*4
	unpacked_row += row[9] #count
	return unpacked_row


def unpack_ack(rule):
	if int(rule[9]) == 2:
		return "yes"
	elif int(rule[9]) == 1:
		return "no"
	else:
		return "any"


def unpack_addr_with_mask(rule, ind):
	unpacked_addr = ""
	unpacked_addr += unpack_addr(rule, ind) + '/'
	#binary = bin(int(rule[ind+1]))
	#unpacked_addr += str(len([ones for ones in binary[2:] if ones=='1']))
	unpack_addr += rule[ind+1]
	return unpack_addr


def unpack_rule(rule):
	unpacked_rule = ""
	unpacked_row += rule[0] + '\t'*4
	unpacked_row += unpack_addr_with_mask(rule, 2) + '\t'*4
	unpacked_row += unpack_addr_with_mask(rule, 4) + '\t'*4
	unpacked_row += unpack_protocol(rule, 6) + '\t'*4
	unpacked_row += unpack_port(rule, 7) + '\t'*4
	unpacked_row += unpack_port(rule, 8) + '\t'*4
	unpacked_row += unpack_ack(rule) + '\t'*4
	unpacked_row += unpack_answer(rule, 10)
	return unpacked_row



def print_log(log):
	log_rows = log.split('#')
	toprint = []
	#num_of_rows = log.split('$')+1
	for row in log_rows:
		#row = row.replace('$', '\t'*4)
		unpacked_row = unpack_row(row.split('$'))
		toprint.append(unpacked_row)
	print '\n'.join(toprint)
		

def print_rules(rules):
	rows = rules.split('#')
	toprint = []
	for rule in rows:
		unpacked_rule = unpack_rule(rule.split('$'))
		toprint.append(unpacked_rule)
	print '\n'.join(toprint)


def execute_command(argv):
	"""As its' name says, this function executes the command passed as a command line argument for the program."""
	if len(argv) == 2:
		cmd = argv[1]
		if cmd == "show_rules":
			validate_path(RULES_PATH)
			print_rules(read(RULES_PATH))
		elif cmd == "show_log":
			validate_path(SHOW_LOG_PATH)
			print_log(read(SHOW_LOG_PATH))
		elif cmd == "clear_log":
			validate_path(RESET_LOG_PATH)
			with open(RESET_LOG_PATH, "w+") as writer:
				writer.write("0")
		else:
			sys.exit("Error: Illegal Command")
	elif len(argv) == 3:
		cmd = argv[1]
		if cmd == "load_rules" and os.path.exists(argv[2]):
			rules = read(argv[2])
			rules = parse_rules(rules)
			if rules != "ERROR":
				with open(RULES_PATH, "w+") as writer:
					writer.write(rules)
	else:
		exit("Usage: python %s <command>" % argv[0])	

def main(argv):
	execute_command(argv)

if __name__ == '__main__':
	main(sys.argv)