#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_restplus import fields
from app import api


groups_fields_attributes = api.model('GroupsFieldsAttributes', {
    'name': fields.String
})

groups_fields_attributes_post = api.model('GroupsFieldsAttributesPost', {
    'name': fields.String(required=True, pattern='^(?!\s*$).+')
})

groups_fields_with_relationships_post_put = api.model('GroupsFieldsWithRelationshipsPost', {
    'relationships': fields.Nested(api.model('GroupsRelationshipsPost', {
        'users': fields.Nested(api.model('GroupsDataPost', {
            'data': fields.Nested(api.model('GroupsPostData', {
                'type': fields.String,
                'id': fields.Integer
            }), as_list=True)
        })),
        'abilities': fields.Nested(api.model('ContainersDataPost', {
            'data': fields.Nested(api.model('ContainersPostData', {
                'type': fields.String,
                'id': fields.Integer
            }), as_list=True)
        }))
    }))
})

_groups_fields_get = api.inherit('GroupsFieldsGet', groups_fields_with_relationships_post_put, {
    'type': fields.String(default='groups'),
    'id': fields.Integer,
    'attributes': fields.Nested(groups_fields_attributes),
})

_groups_fields_post = api.inherit('GroupsFieldsPost', groups_fields_with_relationships_post_put, {
    'type': fields.String(pattern='groups', default='groups'),
    'attributes': fields.Nested(groups_fields_attributes_post),
})

_groups_fields_put = api.inherit('GroupsFieldsPut', groups_fields_with_relationships_post_put, {
    'type': fields.String(pattern='groups', default='groups'),
    'attributes': fields.Nested(groups_fields_attributes),
})


groups_fields_get = api.model('GroupsRootGet', { 'data': fields.Nested(_groups_fields_get) })
groups_fields_get_many = api.model('GroupsRootGetMany', { 'data': fields.Nested(_groups_fields_get, as_list=True) })
groups_fields_post = api.model('GroupsRootPost', { 'data': fields.Nested(_groups_fields_post) })
groups_fields_put = api.model('GroupsRootPut', { 'data': fields.Nested(_groups_fields_put) })
