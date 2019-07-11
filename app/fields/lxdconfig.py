#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_restplus import fields
from app import api

lxdconfig_fields_attributes = api.model('_LXDConfigAttributes', {
    'endpoint': fields.String(),
    'cert_crt': fields.String(),
    'cert_key': fields.String(),
    'verify': fields.String(),
    'sender': fields.String(),
    'recipient': fields.String(),
    'server': fields.String(),
    'port': fields.String(),
    'login': fields.String(),
    'password': fields.String(),
    'production_name': fields.String()
    }
)

_lxdconfig_fields_get = api.model('LXDConfigFieldsGet', {
    'type': fields.String(default='lxdconfig'),
    'attributes': fields.Nested(lxdconfig_fields_attributes),
    'id': fields.Integer(default=1)
})

lxdconfig_fields_get = api.model('LXDConfigGet', {'data': fields.Nested(_lxdconfig_fields_get)})

lxdconfig_fields_post = api.model('LXDConfigPost', {
    'endpoint': fields.String(required=True),
    'cert_crt': fields.String(required=True),
    'cert_key': fields.String(required=True),
    'verify': fields.String(required=True, default='False'),
    'sender': fields.String(required=True),
    'recipient': fields.String(required=True),
    'server': fields.String(required=True),
    'port': fields.String(required=True),
    'login': fields.String(required=True),
    'password': fields.String(required=True),
    'production_name': fields.String(required=True)
    }
)