import os

from rq import Worker, Queue, Connection

import lib


if __name__ == '__main__':
    lib.login_to_redis()
    lib.login_to_cloudflare()
    with Connection(lib.redis):
        worker = Worker([Queue()])
        worker.work()
