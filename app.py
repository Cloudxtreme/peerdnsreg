import os
import time

from flask import abort, Flask, request
import rq

import lib


app = lib.app = Flask(__name__)

if lib.DEBUG:
    methods = ['POST', 'GET']
else:
    methods = ['POST']


lib.login_to_redis()
lib.login_to_cloudflare()
q = rq.Queue(connection=lib.redis)


@lib.check_and_route('/register', methods=methods)
def register():
    name = lib.get_param('name')
    ip = lib.get_param('ip')
    q.enqueue(lib.register, name, ip)
    return "OK"

@lib.check_and_route('/unregister', methods=methods)
def unregister():
    name = lib.get_param('name')
    q.enqueue(lib.unregister, name)
    return "OK"

@lib.check_and_route('/publish/<msg>')
def publish(msg):
    nsubscribers = lib.redis.publish('test', msg)
    return "Published %r to %d subscribers, OK." % (msg, nsubscribers)
