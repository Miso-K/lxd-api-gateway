#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_restplus import fields
from app import api


snapshots_fields_attributes = api.model('SnapshotsFieldsAttributes', {
    'name': fields.String,
    'created_at': fields.String,
    'stateful': fields.String
})

snapshots_fields_attributes_post = api.model('SnapshotsFieldsAttributesPost', {
    'name': fields.String(required=True, pattern='^(?!\s*$).+'),
    'stateful': fields.String
})

snapshots_fields_attributes_put = api.model('SnapshotsFieldsAttributesPut', {
    'name': fields.String(required=True, pattern='^(?!\s*$).+'),
    'stateful': fields.String
})


_snapshots_fields_get = api.model('SnapshotsFieldsGet', {
    'type': fields.String(default='snapshots'),
    'attributes': fields.Nested(snapshots_fields_attributes),
})

_snapshots_fields_post = api.inherit('SnapshotsFieldsPost', {
    'type': fields.String(pattern='snapshots', default='snapshots'),
    'attributes': fields.Nested(snapshots_fields_attributes_post),
})

_snapshots_fields_put = api.inherit('SnapshotsFieldsPut', {
    'type': fields.String(pattern='snapshots', default='snapshots'),
    'attributes': fields.Nested(snapshots_fields_attributes_put),
})


snapshots_fields_get = api.model('SnapshotsRootGet', { 'data': fields.Nested(_snapshots_fields_get) })
snapshots_fields_get_many = api.model('SnapshotsRootGetMany', { 'data': fields.Nested(_snapshots_fields_get, as_list=True) })
snapshots_fields_post = api.model('SnapshotsRootPost', { 'data': fields.Nested(_snapshots_fields_post) })
snapshots_fields_put = api.model('SnapshotsRootPut', { 'data': fields.Nested(_snapshots_fields_put) })