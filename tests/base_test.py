from threading import Thread
import time
from config_tests import *

def BaseTests(object):
    def __init__(create_connection, assert_recv_eq):
        self.create_connection = create_connection
        self.assert_recv_eq = assert_recv_eq

    def all_in_one(self):
        conn = self.create_connection()
        for test in tests:
            self.assert_recv_eq(conn, test)
        conn.close()

    def one_by_one(self):
        for test in tests:
            conn = self.create_connection()
            self.assert_recv_eq(conn, test)
            conn.close()

    def concurrent_with_different_task(self):
        def start_conn(test):
            time.sleep(0.1)
            conn = self.create_connection()
            self.assert_recv_eq(conn, test)
            conn.close()

        threads = [Thread(target=start_conn, args=(t,)) for t in tests]
        [thread.start() for thread in threads]
        [thread.join() for thread in threads]

    def concurrent_all_in_one(self):
        threads = [Thread(target=self.all_in_one) for _ in tests]
        [thread.start() for thread in threads]
        [thread.join() for thread in threads]
