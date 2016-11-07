import time
from threading import Thread

PROXY_PORT = 8010
SERVER_PORT = 9000
BUF_SIZE = 8192

tests = [
    b'a',
    b'ab',
    b'abc' * 30,
    b'1' * 1024,
    b'2' * BUF_SIZE,
]

def p(fmt, data, mode=None, limit=40):
    if mode == 'hex':
        data = map(lambda b: format(ord(b), '02x'), data)
    else:
        data = map(ord, data)

    if len(data) > limit:
        fmt += ' ... (%d)'
        print(fmt % (data[:limit], len(data)))
    else:
        print(fmt % data)

class BaseTests(object):
    def __init__(self, create_connection, assert_recv_eq):
        self._create_connection = create_connection
        self._assert_recv_eq = assert_recv_eq
        self._fmt = """def test_{1}():
            return {0}.{1}()"""

    def _create_defs(self, name):
        methods = [m for m in dir(self) if not m.startswith('_')]
        defs = []
        for m in methods:
            defs.append(self._fmt.format(name, m))
        return defs

    def all_in_one(self):
        conn = self._create_connection()
        for test in tests:
            self._assert_recv_eq(conn, test)
        conn.close()

    def one_by_one(self):
        for test in tests:
            conn = self._create_connection()
            self._assert_recv_eq(conn, test)
            conn.close()

    def concurrent_with_different_task(self):
        def start_conn(test):
            time.sleep(0.1)
            conn = self._create_connection()
            self._assert_recv_eq(conn, test)
            conn.close()

        threads = [Thread(target=start_conn, args=(t,)) for t in tests]
        [thread.start() for thread in threads]
        [thread.join() for thread in threads]

    def concurrent_all_in_one(self):
        threads = [Thread(target=self.all_in_one) for _ in tests]
        [thread.start() for thread in threads]
        [thread.join() for thread in threads]
