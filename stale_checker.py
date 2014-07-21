from pprint import pprint
import signal
import time
import traceback

import rq

import lib


def run():
    print "starting expirer"
    class Done(Exception):
        pass
    def handler(signum, frame):
        print "stale_checker handling SIGTERM"
        raise Done
    signal.signal(signal.SIGTERM, handler)
    try:
        print "stale checker logging in to redis"
        lib.login_to_redis()
        print "stale_checker logged in to redis"
        q = rq.Queue(connection=lib.redis)
        while True:
            q.enqueue(lib.remove_stale_entries)
            time.sleep(lib.CHECK_STALE_PERIOD)
    except Done:
        print "stale_checker caught SIGTERM; bye!"



if __name__ == '__main__':
    try:
        run()
    except:
        traceback.print_exc()
