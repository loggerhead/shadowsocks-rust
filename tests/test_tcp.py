#!/usr/bin/env python
from threading import Thread
import socket
import socks

SERVER_IP = '127.0.0.1'
SERVER_PORT = 8010

data = b'first data'

r1 = 1
r2 = 2

def start_server():
    s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((SERVER_IP, 9000))
    s.listen(5)
    conn, _ = s.accept()
    global r2
    r2 = conn.recv(4096)
    conn.sendall(data)
    s.close()

def start_client():
    c = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    c.set_proxy(socks.SOCKS5, SERVER_IP, SERVER_PORT)
    c.connect((SERVER_IP, 9000))
    c.sendall(data)
    global r1
    r1 = c.recv(4096)
    c.close()

ts = [
    Thread(target=start_server),
    Thread(target=start_client),
]

import time
for t in ts:
    t.start()
    time.sleep(0.1)

print("client: %s" % r1)
print("server: %s" % r2)
assert r1 == r2
