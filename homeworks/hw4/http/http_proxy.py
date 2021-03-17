import socketserver
import socket, sys
import struct

HTTP_DELIMITER = '\r\n\r\n'
HTTP_PORT = 80
HTTP_PROXY_PORT = 800
CONNS_PATH = "/sys/class/fw/conns/conns"

contains_zip_file = lambda payload: b'Content-Type: application/zip' in payload 
contains_csv_file = lambda payload: b'Content-Type: text/csv' in payload

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


def get_http_header(payload):
	payload = payload.decode('utf-8')
	delim_index = payload.index(HTTP_DELIMITER)
	return payload[:delim_index]



class MyHttpHandler(socketserver.StreamRequestHandler):

	def handle(self):
		client_ip = self.client_address[0]
		client_port = self.client_address[1]
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
			dst_ip = get_dst_ip(client_ip, client_port)
			if dst_ip is None:
				raise Exception
			sock.connect((dst_ip, HTTP_PORT))
			response = b''
			request = self.rfile.readline().strip()				
			print("Data received from http client is: {}".format(request))
			sock.sendall(request)
			while len(response) != 8192:
				data = sock.recv(8192)
				response += data
				if len(response) <= 8192:
					break
			header = response#get_http_header(response)
			if contains_zip_file(header):
				print("ZIP file detected in http reponse from {} !".format(dst_ip))
				sock.close()
				return None
			elif contains_csv_file(header):
				print("CSV file detected in http reponse from {} !".format(dst_ip))
				sock.close()
				return None

			self.wfile.write(response)#.encode())
			print("Data received from http server is: {}".format(response))
		except Exception as e:
			print("Error : %s" % e)
		finally:
			sock.close()


		#self.wfile.write("Hello client...got your message".encode())

def run_proxy():
	socketserver.TCPServer.allow_reuse_address = True
	try:
		http_proxy = socketserver.TCPServer(('0.0.0.0', HTTP_PROXY_PORT), MyHttpHandler)
		http_proxy.serve_forever()
	except KeyboardInterrupt as kbi:
		print("")
	finally:
		http_proxy.server_close()

if __name__ == '__main__':
	run_proxy()
	print("Closing The Http Proxy Server...\nDone")