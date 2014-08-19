from contextlib import contextmanager
from datetime import datetime
import os
import time
import traceback
from functools import wraps

from flask import abort, request
import redis as redis_module
import pyflare
import socket
import ssl


app = None
AUTH_TOKEN = os.getenv('AUTH_TOKEN')
DEBUG = os.getenv('DEBUG') == 'true'
CF_ZONE = 'getiantem.org'
CF_ROUND_ROBIN_SUBDOMAIN = 'roundrobin'
OWN_RECID_KEY = 'own_recid'
ROUND_ROBIN_RECID_KEY = 'rr_recid'
DO_CHECK_AUTH = False
NAME_BY_TIMESTAMP_KEY = 'name_by_ts'

MINUTE = 60
#STALE_TIME = 2 * MINUTE
STALE_TIME = 40

redis = None
cloudflare = None

def register(name, ip):
    print "Processing register for peer: %s" % ip

    '''
    if not check_server(ip):
        print "Could not connect to newly registered peer at %s" % ip
    else:
        rh = redis.hgetall(rh_key(name))
        if rh:
            refresh_record(name, ip, rh)
        else:
            add_new_record(name, ip)
            '''
            

def unregister(name):
    rh = redis.hgetall(rh_key(name))
    if not rh:
        print "***ERROR: trying to unregister non existent name: %r" % name
        return
    for subdomain, key in [(CF_ROUND_ROBIN_SUBDOMAIN, ROUND_ROBIN_RECID_KEY),
                           (name, OWN_RECID_KEY)]:

        try:
            cloudflare.rec_delete(CF_ZONE, rh[key])
        except KeyError, e:
            print "Record missing? %s" % e
    with transaction() as rt:
        rt.zrem(NAME_BY_TIMESTAMP_KEY, name)
        rt.delete(rh_key(name))
        
    print "record deleted OK"

def check_server(address):
    s_ = socket.socket()
    s = ssl.wrap_socket(s_)
    s.settimeout(3)
    port = 443
    print "Attempting to connect to %s on port %s" % (address, port)
    try:
        s.connect((address, port))
        print "Successful connection to %s on port %s" % (address, port)

        # Make sure we close the socket immediately.
        print "Closing socket..."
        s.close()
        return True
    except socket.error, e:
        print "Failed connection to %s on port %s failed: %s" % (address, port, e)
        return False

def refresh_record(name, ip, rh):
    print "refreshing record for %s (%s), redis hash %s" % (name, ip, rh)
    if rh['ip'] == ip:
        print "IP is alright; leaving cloudflare alone"
    else:
        print "Refreshing IP in cloudflare"
        for subdomain, key in [(CF_ROUND_ROBIN_SUBDOMAIN,
                                ROUND_ROBIN_RECID_KEY),
                                (name, OWN_RECID_KEY)]:

            cloudflare.rec_edit(CF_ZONE,
                                'A',
                                rh[key],
                                subdomain,
                                ip,
                                ttl=6*60,
                                service_mode=1)
    with transaction() as rt:
        rt.hmset(rh_key(name), {'last_updated': redis_datetime(), 'ip': ip})
        rt.zadd(NAME_BY_TIMESTAMP_KEY, name, redis_timestamp())
    print "record updated OK"

def add_new_record(name, ip):
    print "adding new record for %s (%s)" % (name, ip)
    rh = {"ip": ip}
    for subdomain, key in [(CF_ROUND_ROBIN_SUBDOMAIN, 'rr_recid'),
                           (name, 'own_recid')]:

        response = cloudflare.rec_new(CF_ZONE,
                                      'A',
                                      subdomain,
                                      ip, 
                                      ttl=6*60)
        rh[key] = recid = response['response']['rec']['obj']['rec_id']
        # Set service_mode to "orange cloud".  For some reason we can't do
        # this on rec_new.
        cloudflare.rec_edit(CF_ZONE,
                            'A',
                            recid,
                            subdomain,
                            ip,
                            ttl=6*60,
                            service_mode=1)
    rh['last_updated'] = redis_datetime()
    with transaction() as rt:
        rt.hmset(rh_key(name), rh)
        rt.zadd(NAME_BY_TIMESTAMP_KEY, name, redis_timestamp())
    print "record added OK"

def remove_stale_entries():
    cutoff = time.time() - STALE_TIME
    for name in redis.zrangebyscore(NAME_BY_TIMESTAMP_KEY,
                                        '-inf',
                                        cutoff):
        try:
            unregister(name)
            print "Unregistered", name
        except:
            print "Exception unregistering %s:" % name
            traceback.print_exc()

@contextmanager
def transaction():
    txn = redis.pipeline(transaction=True)
    yield txn
    txn.execute()

def rh_key(name):
    return 'cf:%s' % name

def redis_datetime():
    "Human-readable version, for debugging."
    return str(datetime.utcnow())

def redis_timestamp():
    "Seconds since epoch, used for sorting."
    return time.time()

def login_to_redis():
    global redis
    redis = redis_module.from_url(os.environ['REDISCLOUD_URL'])

def login_to_cloudflare():
    global cloudflare
    cloudflare = pyflare.Pyflare(os.environ['CLOUDFLARE_USER'],
                                 os.environ['CLOUDFLARE_API_KEY'])

def get_param(name):
    return request.args.get(name, request.form.get(name))

def get_header(name):
    return request.headers.get(name)

def check_auth():
    if DO_CHECK_AUTH and get_param('auth-token') != AUTH_TOKEN:
        abort(403)

def checks_auth(fn):
    @wraps(fn)
    def deco(*args, **kw):
        check_auth()
        return fn(*args, **kw)
    return deco

def log_tracebacks(fn):
    @wraps(fn)
    def deco(*args, **kw):
        try:
            return fn(*args, **kw)
        except:
            return "<pre>" + traceback.format_exc() + "</pre>"
    return deco

def check_and_route(*args, **kw):
    def deco(fn):
        ret = checks_auth(fn)
        if DEBUG:
            ret = log_tracebacks(ret)
        return app.route(*args, **kw)(fn)
    return deco
