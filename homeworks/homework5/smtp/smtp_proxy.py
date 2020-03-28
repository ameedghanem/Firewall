import socketserver
import socket, sys
import struct

SMTP_PORT = 25
SMTP_PROXY_PORT = 250
CONNS_PATH = "/sys/class/fw/conns/conns"




keywords = {
	'auto', 	'double', 	'int', 		'struct',
	'brek', 	'else', 	'long', 	'switch',
	'case', 	'enum', 	'register', 'typedef',
	'char', 	'extern', 	'return', 	'union',
	'continue', 'for', 		'signed', 	'void',
	'do', 		'if', 		'static', 	'while',
	'default', 	'goto', 	'sizeof', 	'volatile',
	'const', 	'float', 	'short', 	'unsigned'
}

library_funcs = {
	'printf', 'scanf', 'strcmp', 'strncmp',
	'strlen', 'gets', 'puts', 'fopen',
	'fclose', 'strstr', 'strtok', 'getchar',
	'putchar', 'strcat', 'strcpy', 'strncpy',
}

includes = {
	'#include <stdio.h>',
	'#include <string.h>',
	'#include <stdlib.h>',
	'#include <time.h>',
	'#define'
}

pointers_types = {
	'void*',	'void**',
	'char*',	'char**',
	'int*',		'int**',
}



def is_keyword(word):
	for kword in keywords:
		if word.startswith(kword):
			return True
	return False

def is_library_func(word):
	for kword in library_funcs:
		if word.startswith(kword):
			return True
	return False

def is_include(word):
	for kword in includes:
		if word.startswith(kword):
			return True
	return False

def is_pointer(word):
	for kword in pointers_types:
		if word.startswith(kword):
			return True
	return False

def is_c_code(text):
	num_keywords = .0
	num_library_funcs = .0
	num_includes = .0
	num_pointers = .0
	num_semi_colon = .0
	num_words = len(text.split())
	for word in text:
		if is_keyword(word):
			num_keywords += 1
		if is_library_func(word):
			num_library_funcs += 1
		if is_include(word):
			num_includes += 1
		if is_pointer(word):
			num_pointers += 1
		if word.endswith(';'):
			num_semi_colon += 1
	if (num_pointers + num_includes + num_keywords + num_library_funcs + num_semi_colon)/num_words >= 0.11: #this means its a c code!
		return True
		

def unpack_addr(row, ind):
	s = socket.inet_ntoa(struct.pack("!I", int(row[ind])))
	slist = s.split('.')
	slist.reverse()
	return '.'.join(slist)

def unpack_conn(conn):
	if conn[0] == '':
		del(conn[0])
	lst = [0 for i in range(4)]
	lst[0] = unpack_addr(conn, 0)
	lst[1] = conn[1]
	lst[2] = unpack_addr(conn, 2)
	lst[3] = conn[3]
	return lst

def get_conns_table():
	"""
		reads the connection table from the conns device.
	"""
	conns_string = ""
	with open(CONNS_PATH, "r") as reader:
		conns_string = reader.read()
	if "no conns" in conns_string:
		return None
	conns = conns_string.split('#')
	if '\n' in conns:
		conns.pop(conns.index('\n'))
	conn_table = []
	for conn in conns:
		curr_conn, reverse_curr_conn = conn.split('*')
		curr_conn, reverse_curr_conn = unpack_conn(curr_conn.split('$')), unpack_conn(reverse_curr_conn.split('$'))
		conn_table.append((curr_conn, reverse_curr_conn))#this will separate between each connection
	return conn_table


def get_dst_ip(src_ip, src_port):
	conns = get_conns_table()
	if conns != None:
		for conn in conns:
			if conn[0][0] == src_ip and int(conn[0][1]) == int(src_port):
				return conn[0][2]
			elif conn[1][0] == src_ip and int(conn[1][1]) == int(src_port):
				return conn[1][2]
	return None



class MySmtpHandler(socketserver.StreamRequestHandler):

	def handle(self):
		client_ip = self.client_address[0]
		client_port = self.client_address[1]
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
			dst_ip = get_dst_ip(client_ip, client_port)
			if dst_ip is None:
				raise Exception
			sock.connect((dst_ip, SMTP_PORT))
			mydata = ''
			while True:
				mail_message = self.rfile.readline().strip()				
				print("Data received from smtp client is: {}".format(mail_message))
				if is_c_code(mail_message[mail_message.index('\r\n')+2:]):
					sock.close()
					return None
				sock.sendall(mail_message)
				while len(mydata) != 10000:
					data = sock.recv(10000)
					mydata += data
					if len(mydata) <= 10000:
						break

				self.wfile.write(mydata)#.encode())
				print("Data received from smtp server is: {}".format(mydata))
		except Exception as e:
			print("Error : %s" % e)
		finally:
			sock.close()


		#self.wfile.write("Hello client...got your message".encode())

def run_proxy():
	socketserver.TCPServer.allow_reuse_address = True
	try:
		http_proxy = socketserver.TCPServer(('0.0.0.0', SMTP_PROXY_PORT), MySmtpHandler)
		http_proxy.serve_forever()
	except KeyboardInterrupt as kbi:
		print("wewe")
	finally:
		http_proxy.server_close()

if __name__ == '__main__':
	run_proxy()
	print("Closing The Http Proxy Server...\nDone")