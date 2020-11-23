#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_restplus import fields
from app import api

lxdconfig_fields_attributes = api.model('_LXDConfigAttributes', {
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
    'data': fields.Raw
    }
)