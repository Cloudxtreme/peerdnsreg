#!/usr/bin/env python

# Assumes a copy of the too-many-secrets repo as a sibling of the directory
# where this is contained.
#
# To import this config for running locally:
#
#    heroku plugins:install git://github.com/ddollar/heroku-config.git
#    heroku config:pull --overwrite
#
# And then you may want to change DEBUG to 'true'.

import os
import sys

import yaml


here = os.path.dirname(sys.argv[0])
secret_repo = os.path.join(here, '..', 'too-many-secrets')
pdr_secrets = yaml.load(file(os.path.join(secret_repo,
                                          'peerdnsreg.txt')))
cf_secrets = yaml.load(file(os.path.join(secret_repo,
                                         'cloudflare.txt')))

def setcfg(name, secret):
    os.system("heroku config:set %s=%s" % (name, secret))

setcfg("CLOUDFLARE_USER", cf_secrets['user'])
setcfg("CLOUDFLARE_API_KEY", cf_secrets['api_key'])
setcfg("AUTH_TOKEN", pdr_secrets['auth_token'])
setcfg("WEB_CONCURRENCY", 2)
setcfg("DEBUG", 'false')
