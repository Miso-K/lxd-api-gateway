#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_restplus import fields
from app import api

lxdcerts_fields_get = api.model('LXDCertsGet', { 'status': fields.String })
lxdcerts_fields_post = api.model('LXDCerstPost', {
    'cert_crt': fields.String(required=True),
    'cert_key': fields.String(required=True)
    }
)
