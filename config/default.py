#!/usr/bin/env python
# -*- coding: utf-8 -*-
from datetime import timedelta

SSL = False
# Easy way : make-ssl-cert generate-default-snakeoil --force-overwrite
SSL_CERT = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
SSL_KEY = '/etc/ssl/private/ssl-cert-snakeoil.key'


DEBUG = False

SQLALCHEMY_DATABASE_URI = 'sqlite:///../lxd-api-gateway.sqlite'
SQLALCHEMY_COMMIT_ON_TEARDOWN = False
SQLALCHEMY_TRACK_MODIFICATIONS = False

JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
JWT_HEADER_TYPE = 'Bearer'

SWAGGER_UI_DOC_EXPANSION = 'list'  # none, list or full

ALLOW_ORIGIN = '*'  # CORS

# Set this config keys before run to production
SECRET_KEY = u'ça cest une vrai appli ! il faut que la clé soit bien longue'
JWT_SECRET_KEY = u'ça cest une vrai appli ! il faut que la clé soit bien longue'

# REDIS CONFIG
JWT_BLACKLIST_ENABLED = True
JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']

REDIS_HOST = '127.0.0.1'
REDIS_PORT = '6379'

OTP_ACCESS_TOKEN_EXPIRES = 7 * 60
ACCESS_TOKEN_EXPIRES = 31 * 60
REFRESH_TOKEN_EXPIRES = 36 * 60
