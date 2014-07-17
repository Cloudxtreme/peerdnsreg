from contextlib import contextmanager
from datetime import datetime
import os
import time
import traceback
from functools import wraps

from fastly import connect as connect_to_fastly, FastlyError
from flask import abort, request
import pyflare
import redis as redis_module


app = None
AUTH_TOKEN = os.getenv('AUTH_TOKEN')
DEBUG = os.getenv('DEBUG') == 'true'
DOMAIN = 'getiantem.org'
CF_ROUND_ROBIN_SUBDOMAIN = 'peerroundrobin'
OWN_RECID_KEY = 'own_recid'
ROUND_ROBIN_RECID_KEY = 'rr_recid'
DO_CHECK_AUTH = False  # clients are registering directly in this MVP
NAME_BY_TIMESTAMP_KEY = 'name_by_ts'
MINUTE = 60
CHECK_STALE_PERIOD = 1 * MINUTE
STALE_TIME = 5 * MINUTE
DIRECTOR_NAME = "PeerAutoDirector"
DIRECTOR_QUORUM_PERCENTAGE = 1
DIRECTOR_RETRIES = 10
FP_PREFIX = "fp-"

cloudflare = None
fastly = None
redis = None

def register(name, ip, port):
    int_port = int(port)
    if int_port <= 0 or int_port > 65535:
        print "***ERROR: trying to register with invalid port: %s" % int_port
        return

    address = "%s:%d" % (ip, port)
    peers = redis.hgetall("peers")
    peer_known = name in peers
    needs_update = not peer_known or peers[name] != address
    if needs_update:
        peers[name] = address
        update_vcl(peers)
        redis.hset("peers", name, address)

def unregister(name):
    peers = redis.hgetall("peers")
    peer_known = name in peers
    if not peer_known:
        print "***ERROR: trying to unregister non existent name: %r" % name
        return
    else:
        del peers[name]
        update_vcl(peers)
        redis.hdel("peers", name)

def update_vcl(peers):
    # TODO: generate VCL here using the templates defined at the end of this file and upload it to Fastly
    pass

def fastly_svcid():
    return os.environ['FASTLY_SERVICE_ID']

@contextmanager
def fastly_version():
    svcid = fastly_svcid()
    edit_version = int(os.environ['FASTLY_VERSION'])
    yield edit_version
    new_version = fastly.clone_version(fastly_svcid(), edit_version)
    fastly.activate_version(svcid, new_version.number)

def remove_stale_entries():
    cutoff = time.time() - STALE_TIME
    for name in redis.zrangebyscore(NAME_BY_TIMESTAMP_KEY,
                                    '-inf',
                                    cutoff):
        try:
            unregister(name)
        except:
            print "Exception unregistering %s:" % name
            traceback.print_exc()

# Cloudflare stuff commented out for future reference.  Some refactoring will
# be in order when we want to bring this back.
#
#def add_cf_record(name, ip):
#    print "adding new record for %s (%s)" % (name, ip)
#    rh = {"ip": ip}
#    for subdomain, key in [(CF_ROUND_ROBIN_SUBDOMAIN, 'rr_recid'),
#                           (name, 'own_recid')]:
#        response = cloudflare.rec_new(DOMAIN,
#                                      'A',
#                                      subdomain,
#                                      ip)
#        rh[key] = recid = response['response']['rec']['obj']['rec_id']
#        # Set service_mode to "orange cloud".  For some reason we can't do
#        # this on rec_new.
#        cloudflare.rec_edit(DOMAIN,
#                            'A',
#                            recid,
#                            subdomain,
#                            ip,
#                            service_mode=1)
#    rh['last_updated'] = redis_datetime()
#    with transaction() as rt:
#        rt.hmset(rh_key(name), rh)
#        rt.zadd(NAME_BY_TIMESTAMP_KEY, name, redis_timestamp())
#    print "record added OK"
#
#def refresh_cf_record(name, ip, rh):
#    print "refreshing record for %s (%s), redis hash %s" % (name, ip, rh)
#    if rh['ip'] == ip:
#        print "IP is alright; leaving cloudflare alone"
#    else:
#        print "refreshing IP in cloudflare"
#        for subdomain, key in [(CF_ROUND_ROBIN_SUBDOMAIN,
#                                ROUND_ROBIN_RECID_KEY),
#                                (name, OWN_RECID_KEY)]:
#            cloudflare.rec_edit(DOMAIN,
#                                'A',
#                                rh[key],
#                                subdomain,
#                                ip,
#                                service_mode=1)
#    with transaction() as rt:
#        rt.hmset(rh_key(name), {'last_updated': redis_datetime(), 'ip': ip})
#        rt.zadd(NAME_BY_TIMESTAMP_KEY, name, redis_timestamp())
#    print "record updated OK"
#
#def remove_cf_record(name, rh):
#    for subdomain, key in [(CF_ROUND_ROBIN_SUBDOMAIN, ROUND_ROBIN_RECID_KEY),
#                           (name, OWN_RECID_KEY)]:
#        cloudflare.rec_delete(DOMAIN, rh[key])
#    with transaction() as rt:
#        rt.delete(rh_key(name))
#        rt.zrem(NAME_BY_TIMESTAMP_KEY, name)
#    print "record deleted OK"

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

def login_to_fastly():
    global fastly
    fastly = connect_to_fastly(os.environ['FASTLY_API_KEY'])
    fastly.login(os.environ['FASTLY_USER'],
                 os.environ['FASTLY_PASSWORD'])

def login_to_cloudflare():
    global cloudflare
    cloudflare = pyflare.Pyflare(os.environ['CLOUDFLARE_USER'],
                                 os.environ['CLOUDFLARE_API_KEY'])

def get_param(name):
    return request.args.get(name, request.form.get(name))

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
        return app.route(*args, **kw)(ret)
    return deco

BACKEND_TEMPLATE = """
backend F_%d {
    .connect_timeout = 10s;
    .port = "%s";
    .host = "%s";
    .first_byte_timeout = 30s;
    .saintmode_threshold = 200000;
    .max_connections = 100;
    .between_bytes_timeout = 80s;
    .share_key = "11yqoXJrAAGxPiC07v3q9Z";
      
    .probe = {
        .request = "HEAD / HTTP/1.1" "Host: getiantem.org" "Connection: close""User-Agent: Varnish/fastly (healthcheck)";
        .threshold = 3;
        .window = 5;
        .timeout = 5s;
        .initial = 4;
        .expected_response = 200;
        .interval = 15s;
      }
}
"""

DIRECTOR_BACKEND_TEMPLATE = """
{
    .backend = F_%d;
    .weight  = 100;
}
"""

CONDITION_TEMPLATE = """
if( req.http.host == "%s.getiantem.org" ) {
    set req.backend = F_%d;
}
"""

VCL_TEMPLATE = """
backend F_sp1 {
    .connect_timeout = 10s;
    .port = "80";
    .host = "128.199.176.82";
    .first_byte_timeout = 30s;
    .saintmode_threshold = 200000;
    .max_connections = 20000;
    .between_bytes_timeout = 80s;
    .share_key = "11yqoXJrAAGxPiC07v3q9Z";
      
    .probe = {
        .request = "HEAD / HTTP/1.1" "Host: getiantem.org" "Connection: close""User-Agent: Varnish/fastly (healthcheck)";
        .threshold = 3;
        .window = 5;
        .timeout = 5s;
        .initial = 4;
        .expected_response = 200;
        .interval = 15s;
      }
}

backend F_sp2 {
    .connect_timeout = 10s;
    .port = "80";
    .host = "128.199.178.148";
    .first_byte_timeout = 30s;
    .saintmode_threshold = 200000;
    .max_connections = 20000;
    .between_bytes_timeout = 80s;
    .share_key = "11yqoXJrAAGxPiC07v3q9Z";
      
    .probe = {
        .request = "HEAD / HTTP/1.1" "Host: getiantem.org" "Connection: close""User-Agent: Varnish/fastly (healthcheck)";
        .threshold = 3;
        .window = 5;
        .timeout = 5s;
        .initial = 4;
        .expected_response = 200;
        .interval = 15s;
      }
}

backend F_sp3 {
    .connect_timeout = 10s;
    .port = "80";
    .host = "128.199.140.101";
    .first_byte_timeout = 30s;
    .saintmode_threshold = 200000;
    .max_connections = 20000;
    .between_bytes_timeout = 80s;
    .share_key = "11yqoXJrAAGxPiC07v3q9Z";
      
    .probe = {
        .request = "HEAD / HTTP/1.1" "Host: getiantem.org" "Connection: close""User-Agent: Varnish/fastly (healthcheck)";
        .threshold = 3;
        .window = 5;
        .timeout = 5s;
        .initial = 4;
        .expected_response = 200;
        .interval = 15s;
      }
}

backend F_sp4 {
    .connect_timeout = 10s;
    .port = "80";
    .host = "128.199.140.103";
    .first_byte_timeout = 30s;
    .saintmode_threshold = 200000;
    .max_connections = 20000;
    .between_bytes_timeout = 80s;
    .share_key = "11yqoXJrAAGxPiC07v3q9Z";
      
    .probe = {
        .request = "HEAD / HTTP/1.1" "Host: getiantem.org" "Connection: close""User-Agent: Varnish/fastly (healthcheck)";
        .threshold = 3;
        .window = 5;
        .timeout = 5s;
        .initial = 4;
        .expected_response = 200;
        .interval = 15s;
      }
}

%s

director PeerAutoDirector random {
   .quorum = 1%;
   .retries = 10;
   {
    .backend = F_sp1;
    .weight  = 10000;
   }{
    .backend = F_sp2;
    .weight  = 10000;
   }{
    .backend = F_sp3;
    .weight  = 10000;
   }{
    .backend = F_sp4;
    .weight  = 10000;
   }%s
}

sub vcl_recv {
  set req.backend = PeerAutoDirector;

  # Sticky routing
  if( req.http.host == "sp1.getiantem.org" ) {
    set req.backend = F_sp1;
  }
  if( req.http.host == "sp2.getiantem.org" ) {
    set req.backend = F_sp2;
  }
  if( req.http.host == "sp3.getiantem.org" ) {
    set req.backend = F_sp3;
  }
  if( req.http.host == "sp4.getiantem.org" ) {
    set req.backend = F_sp4;
  }
  %s
  #FASTLY recv
}
"""