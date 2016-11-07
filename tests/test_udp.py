#!/usr/bin/python
import socks
import socket

from config_tests import *

tests.append(b'3' * 1024)
tests.append(b'4' * 4096)

def create_connection():
    conn = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM, socket.SOL_UDP)
    conn.set_proxy(socks.SOCKS5, "127.0.0.1", PROXY_PORT)
    conn.settimeout(3)
    return conn

def assert_recv_eq(conn, test):
    conn.sendto(test, ('127.0.0.1', SERVER_PORT))
    recv, _ = conn.recvfrom(BUF_SIZE + 1024)
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
