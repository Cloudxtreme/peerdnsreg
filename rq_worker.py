import os

from rq import Worker, Queue, Connection

import lib


if __name__ == '__main__':
    #lib.login_to_cloudflare()

    print "Logging in to fastly"
    lib.login_to_fastly()

    print "Logging in to redis"
    lib.login_to_redis()

    print "Logged in to redis"
    with Connection(lib.redis):

        worker = Worker([Queue()])
        worker.work()
