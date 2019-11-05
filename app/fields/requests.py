#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_restplus import fields
from app import api

requests_fields_attributes = api.model('RequestsFieldsAttributes', {
    'action': fields.String,
    'message': fields.String,
    'meta_data': fields.String,
    'status': fields.String,
    'created_on': fields.DateTime(dt_format='rfc822'),
    'changed_on': fields.DateTime(dt_format='rfc822')
})

requests_fields_with_relationships_put = api.model('RequestsFieldsWithRelationshipsPost', {
    'relationships': fields.Nested(api.model('RequestsRelationshipsPost', {
        'users': fields.Nested(api.model('RequestsDataPost', {
            'data': fields.Nested(api.model('RequestsPostData', {
                'type': fields.String(default='users'),
                'id': fields.Integer
            }), as_list=True)
        })),
    }))
})


requests_fields_attributes_put = api.model('RequestsFieldsAttributesPut', {
    'message': fields.String,
    'status': fields.String
})

requests_fields_attributes_post = api.model('RequestsFieldsAttributesPost', {
    'action': fields.String,
    'message': fields.String,
    'status': fields.String,
    'meta_data': fields.String
})

_requests_fields_post = api.inherit('RequestsFieldsPost', requests_fields_with_relationships_put, {
    'type': fields.String(pattern='requests', default='requests'),
    'attributes': fields.Nested(requests_fields_attributes_post),
})

_requests_fields_get = api.inherit('RequestsFieldsGet', requests_fields_with_relationships_put, {
    'type': fields.String(default='requests'),
    'id': fields.Integer,
    'attributes': fields.Nested(requests_fields_attributes),
})

_requests_fields_put = api.inherit('RequestsFieldsPut', requests_fields_with_relationships_put, {
    'type': fields.String(pattern='requests', default='requests'),
    'attributes': fields.Nested(requests_fields_attributes_put),
})


requests_fields_get = api.model('RequestsRootGet', { 'data': fields.Nested(_requests_fields_get) })
requests_fields_get_many = api.model('RequestsRootGetMany', { 'data': fields.Nested(_requests_fields_get, as_list=True) })
requests_fields_put = api.model('RequestsRootPut', { 'data': fields.Nested(_requests_fields_put) })
requests_fields_post = api.model('RequestsRootPost', { 'data': fields.Nested(_requests_fields_post) })
