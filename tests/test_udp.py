#!/usr/bin/python
# This test script is copy from https://github.com/shadowsocks/shadowsocks/blob/master/tests/test_udp_src.py
# So keep the original copyright here:

# Copyright 2014-2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import socket
import socks


SERVER_IP = '127.0.0.1'
SERVER_PORT = 8010


if __name__ == '__main__':
    # Test 1: same source port IPv4
    sock_out = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM,
                                socket.SOL_UDP)
    sock_out.set_proxy(socks.SOCKS5, SERVER_IP, SERVER_PORT)
    sock_out.bind(('127.0.0.1', 9000))

    sock_in1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                             socket.SOL_UDP)
    sock_in2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                             socket.SOL_UDP)

    sock_in1.bind(('127.0.0.1', 9001))
    sock_in2.bind(('127.0.0.1', 9002))

    data = b'first data'
    sock_out.sendto(data, ('127.0.0.1', 9001))
    result1 = sock_in1.recvfrom(len(data))

    sock_out.sendto(data, ('127.0.0.1', 9002))
    result2 = sock_in2.recvfrom(len(data))

    sock_out.close()
    sock_in1.close()
    sock_in2.close()

    # make sure they're from the same source port
    print(repr(result1))
    print(repr(result2))
    assert result1 == result2

    """
    # Test 2: same source port IPv6
    # try again from the same port but IPv6
    sock_out = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM,
                                socket.SOL_UDP)
    sock_out.set_proxy(socks.SOCKS5, SERVER_IP, SERVER_PORT)
    sock_out.bind(('127.0.0.1', 9000))

    sock_in1 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM,
                             socket.SOL_UDP)
    sock_in2 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM,
                             socket.SOL_UDP)

    sock_in1.bind(('::1', 9001))
    sock_in2.bind(('::1', 9002))

    sock_out.sendto(b'data', ('::1', 9001))
    result1 = sock_in1.recvfrom(8)

    sock_out.sendto(b'data', ('::1', 9002))
    result2 = sock_in2.recvfrom(8)

    sock_out.close()
    sock_in1.close()
    sock_in2.close()

    # make sure they're from the same source port
    assert result1 == result2

    # Test 3: different source ports IPv6
    sock_out = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM,
                                socket.SOL_UDP)
    sock_out.set_proxy(socks.SOCKS5, SERVER_IP, SERVER_PORT)
    sock_out.bind(('127.0.0.1', 9003))

    sock_in1 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM,
                             socket.SOL_UDP)
    sock_in1.bind(('::1', 9001))
    sock_out.sendto(b'data', ('::1', 9001))
    result3 = sock_in1.recvfrom(8)

    # make sure they're from different source ports
    assert result1 != result3

    sock_out.close()
    sock_in1.close()
    """
