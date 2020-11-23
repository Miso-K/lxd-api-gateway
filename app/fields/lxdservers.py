#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_restplus import fields
from app import api

_servers_fields_post = api.model('LXDServersPost', {
    'name': fields.String(required=True),
    'address': fields.String(required=True),
    'password': fields.String(required=True),
    'verify': fields.String(required=False),
    'exec_address': fields.String(required=True)
})

servers_fields_with_relationships_get = api.model('ServersFieldsWithRelationshipsGet', {
    'relationships': fields.Nested(api.model('ServersRelationshipsGet', {
        'instances': fields.Nested(api.model('ContainersDataGet', {
            'id': fields.Integer,
            'name': fields.String
        }), as_list=True)
    }))
})

_servers_fields_get = api.inherit('LXDServersGet', servers_fields_with_relationships_get, {
    'type': fields.String(default='servers'),
    'id': fields.Integer,
    'name': fields.String,
    'address': fields.String,
    'exec_address': fields.String,
    'verify': fields.String
})


lxdservers_fields_get = api.model('ServersRootGet', { 'data': fields.Nested(_servers_fields_get) })
lxdservers_fields_get_many = api.model('ServersRootGetMany', { 'data': fields.Nested(_servers_fields_get, as_list=True) })
lxdservers_fields_post = api.model('ServersRootPost', { 'data': fields.Nested(_servers_fields_post) })
#lxdservers_fields_put = api.model('ServersRootPut', { 'data': fields.Nested(_servers_fields_put) })