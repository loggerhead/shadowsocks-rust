#!/usr/bin/python
import socket
import socks

from config_tests import *

tests.append(b'3' * 32 * 1024)
tests.append(b'6' * 64 * 1024)

def create_connection():
    c = socks.socksocket()
    c.settimeout(3)
    c.setblocking(True)
    c.set_proxy(socks.SOCKS5, "127.0.0.1", PROXY_PORT)
    c.connect(("127.0.0.1", SERVER_PORT))
    return c

def assert_recv_eq(conn, test):
    conn.sendall(test)

    recv = b''
    while len(recv) < len(test):
        r = conn.recv(BUF_SIZE)
        if len(r) == 0:
            break
        else:
            recv += r

    try:
        assert recv == test
    except Exception as e:
        p("expect: %s", test)
        p("recv: %s", recv)
        raise e


ts = BaseTests(create_connection, assert_recv_eq)
defs = ts._create_defs("ts")
for d in defs:
    exec(d)
