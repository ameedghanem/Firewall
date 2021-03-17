import os,sys,re
import socket, struct
import logging


PROXY_FTP_CTRL_PORT = 210
PROXY_FTP_DATA_PORT = 209
CONNS_PATH = "/sys/fw/class/conns/conns"
FTP_DEVICE_PATH = "/sys/fw/class/ftp_port_cmd/ftp_port_cmd"

logging.basicConfig(
	level = logging.DEBUG,
	filename = '../.fwlog/ftp.log',
	format = '%(levelname).1s %(asctime)s %(message)s',
	datefmt = '%Y-%m-%d %H:%M:%S',
)
LOG = logging.getLogger()

get_port = lambda p1,p2: 256*p1 + p2 #thie lambda expression returns the port number calcuated from p1,p2 in the ftp PORT command
is_port_command = lambda payload: payload.startsiwith('PORT ')
get_other_side_ip = lambda ip: '10.1.2.2' if ip == '10.1.1.1' else '10.1.1.1'


def write_to_ftp_attr(ip, port):
    return None


class Server(object):

    '''
    Proxy Server compatible for ftp
    '''

    def __init__(self, **kwargs):
        self.severSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.severSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.severSocket.bind((kwargs["hostname"], kwargs["port"]))
        self.clients = []


    @staticmethod
    def recv_data_from_socket(sock):
	""" Reads data from source host """
	data = []
	while True:		
		curr_data = sock.recv(29)
		# make sure we truly received data
		if not curr_data:
			break
		data.append(curr_data)
	return "".join(data)



    def proxy_thread(self, conn, addr):
        proxy_src_ip, proxy_src_port, dst_ip, dst_port = 0, 0, 0, 0
        request = self.recv_data_from_socket(conn)
        print "recieved %s" % request
        LOG.debug("command\n%s" % request)
        src_ip, src_port = conn.getpeername()
        print "peer name: (%s,%d)" %  (src_ip, src_port)

        # Now proxy serve behave like a client
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((get_other_side_ip(src_ip), 20))
        proxy_src_ip, proxy_src_port = sock.getsockname()
        print "connect to %s - %d" % (proxy_src_ip, proxy_src_port)
        proxy_src_ip, proxy_src_port = sock.getsockname()
        proxy_conn_string = '$'.join([proxy_src_ip, str(proxy_src_port), get_other_side_ip(src_ip), str(20)])
        sock.sendall(request)
        mydata = ""

        # Response by a web server
        try:
            while True:
                cmd = recv_data_from_socket(sock)
                print "recived form the %s: %s" % (get_other_side_ip(src_ip), cmd)

                if is_port_command(cmd):
                	packed = cmd[5:]#5 is the len of the 'PORT ', which is the prefix of the port command!!
                	unpacked = packed.split(',')
                    port = get_port(unpacked[4], unpacked[5])
                    ip = '.'.join(unpacked[:4])
                    ip = struct.unpack("!I", socket.inet_aton(ip))[0]


                conn.sendall(cmd)
        except socket.error as error:
            LOG.error(error)
            if sock:
                sock.close()
            if conn:
                conn.close()
        finally:
            return



    def listening(self):
        print("Listening..")
        self.severSocket.listen(10)
        while True:
            # Blocking
            conn, addr = self.severSocket.accept()
            LOG.debug("got a new connection: src_ip = %s ,src_port = %u" % (conn.getpeername()))
            print "got a new connection: src_ip = %s ,src_port = %u" % (conn.getpeername())
            new_thread = threading.Thread(target=self.proxy_thread, args=(conn, addr))
            new_thread.setDaemon(True)
            new_thread.start()
            self.clients.append(new_thread)

    def closing(self):
        self.severSocket.close()
        sys.exit("Closing the server...")


def run_http_proxy():
    proxy = Server(hostname='0.0.0.0', port=PROXY_FTP_CTRL_PORT)
    try:
        proxy.listening()
    finally:
        proxy.closing()



if __name__ == '__main__':
	LOG.debug("======== FTP-PROXY STARTED ========")
	run_fttp_proxy()