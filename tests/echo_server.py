#!/usr/bin/python
import SocketServer
from threading import Thread
from config_tests import SERVER_PORT, BUF_SIZE, p

class TcpEchoHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(BUF_SIZE)
            if len(data) == 0:
                break
            self.request.sendall(data)

class UdpEchoHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        conn = self.request[1]
        conn.sendto(data, self.client_address)

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

class ThreadedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
    pass

def start_tcp_server():
    s = ThreadedTCPServer(("127.0.0.1", SERVER_PORT), TcpEchoHandler)
    s.serve_forever()

def start_udp_server():
    s = ThreadedUDPServer(("127.0.0.1", SERVER_PORT), UdpEchoHandler)
    s.serve_forever()

if __name__ == '__main__':
    Thread(target=start_tcp_server).start()
    Thread(target=start_udp_server).start()
