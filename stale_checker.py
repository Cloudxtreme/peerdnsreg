from pprint import pprint
import signal
import time
import traceback

import lib


MINUTE = 60
SLEEP_TIME = 1 * MINUTE
STALE_TIME = 5 * MINUTE


def run():
    print "starting expirer"
    class Done(Exception):
        pass
    def handler(signum, frame):
        print "handling SIGTERM"
        raise Done
    signal.signal(signal.SIGTERM, handler)
    try:
        lib.login_to_redis()
        lib.login_to_cloudflare()
        while True:
            remove_stale_entries()
            time.sleep(SLEEP_TIME)
    except Done:
        print "Caught SIGTERM; bye!"

def remove_stale_entries():
    cutoff = time.time() - STALE_TIME
    for name in lib.redis.zrangebyscore(lib.NAME_BY_TIMESTAMP_KEY,
                                        '-inf',
                                        cutoff):
        try:
            lib.unregister(name)
            print "Unregistered", name
        except:
            traceback.print_exc()


if __name__ == '__main__':
    try:
        run()
    except:
        traceback.print_exc()
