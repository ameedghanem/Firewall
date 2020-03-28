import os,sys,re
import socket, struct
import logging


PROXY_FTP_CTRL_PORT = 210
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


def write_to_ftp_attr(src_ip, src_port, dst_ip, dst_port):
    lst = [src_ip, src_port, dst_ip, dst_port]
    ftp_str = "$".join(lst)
    with open(FTP_DEVICE_PATH, "b+") as writer:
        writer.write(ftp_str)


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



class MyFtpHandler(socketserver.StreamRequestHandler):

    def handle(self):
        client_ip = self.client_address[0]
        client_port = self.client_address[1]
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            dst_ip = get_dst_ip(client_ip, client_port)
            if dst_ip is None:
                raise Exception
            sock.connect((dst_ip, FTP_PORT))
            cmd = b''
            while True:
                request = self.rfile.readline().strip()             
                print("Data received from ftp client is: {}".format(request))
                sock.sendall(request)
                while len(cmd) != 8192:
                    data = sock.recv(8192)
                    cmd += data
                    if len(cmd) <= 8192:
                        break
                if is_port_command(cmd):
                    packed = cmd[5:]#5 is the len of the 'PORT ', which is the prefix of the port command!!
                    unpacked = packed.split(',')
                    port = get_port(unpacked[4], unpacked[5])
                    ip = '.'.join(unpacked[:4])
                    ip = struct.unpack("!I", socket.inet_aton(ip))[0]
                    #need now to send the firewall the port we got to open a conection entry in its connection table
                    write_to_ftp_attr(dst_ip, FTP_DATA_PORT, client_ip, client_port)


                self.wfile.write(cmd)#.encode())
                print("Data received from ftp server is: {}".format(cmd))
        except Exception as e:
            print("Error : %s" % e)
        finally:
            sock.close()


        #self.wfile.write("Hello client...got your message".encode())

def run_proxy():
    socketserver.TCPServer.allow_reuse_address = True
    try:
        ftp_proxy = socketserver.TCPServer(('0.0.0.0', FTP_PROXY_PORT), MyFtpHandler)
        ftp_proxy.serve_forever()
    except KeyboardInterrupt as kbi:
        print("")
    finally:
        ftp_proxy.server_close()

if __name__ == '__main__':
    run_proxy()
    print("Closing The FTP Proxy Server...\nDone")






































