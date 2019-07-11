#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_restplus import fields, Model
from app import api


users_fields_attributes = api.model('UsersFieldsAttributes', {
    'admin': fields.Boolean(default=False),
    'username': fields.String,
    'name': fields.String,
    'email': fields.String,
    'phone': fields.String,
    'address': fields.String,
    'city': fields.String,
    'country': fields.String,
    'postal_code': fields.String,
    'ico': fields.String,
    'ic_dph': fields.String,
    'dic': fields.String,
    'language': fields.String,
    'registered_on': fields.DateTime(dt_format='rfc822'),
    'otp_enabled': fields.Boolean(default=False),
    'otp_type': fields.String
})

users_fields_attributes_post = api.model('UsersFieldsAttributesPost', {
    'admin': fields.Boolean(default=False),
    'username': fields.String(required=True, pattern='^[a-zA-Z0-9_.-]+$'),
    'name': fields.String(required=True, pattern='^(?!\s*$).+'),
    'email': fields.String(pattern=r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)'),
    'phone': fields.String,
    'address': fields.String,
    'city': fields.String,
    'country': fields.String,
    'postal_code': fields.String,
    'ico': fields.String(pattern='^[0-9_.-]*$'),
    'ic_dph': fields.String(pattern='^[0-9_.-]*$'),
    'dic': fields.String(pattern='^[0-9_.-]*$'),
    'language': fields.String,
    'otp_type': fields.String,
    'password': fields.String(required=True, pattern='^(?!\s*$).+')
})

users_fields_attributes_put = api.model('UsersFieldsAttributesPut', {
    'admin': fields.Boolean(default=False),
    'name': fields.String(pattern='^(?!\s*$).+'),
    'email': fields.String(pattern=r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)'),
    'phone': fields.String,
    'address': fields.String,
    'city': fields.String,
    'country': fields.String,
    'postal_code': fields.String,
    'ico': fields.String(pattern='^[0-9_.-]*$'),
    'ic_dph': fields.String(pattern='^[0-9_.-]*$'),
    'dic': fields.String(pattern='^[0-9_.-]*$'),
    'language': fields.String,
    'otp_type': fields.String,
    'password': fields.String(pattern='^(?!\s*$).+')
})

users_fields_with_relationships_post_put = api.model('UsersFieldsWithRelationshipsPost', {
    'relationships': fields.Nested(api.model('UsersRelationshipsPost', {
        'groups': fields.Nested(api.model('GroupsDataPost', {
            'data': fields.Nested(api.model('GroupsPostData', {
                'type': fields.String,
                'id': fields.Integer
            }), as_list=True)
        })),
        'containers': fields.Nested(api.model('ContainersDataPost', {
            'data': fields.Nested(api.model('ContainersPostData', {
                'type': fields.String,
                'id': fields.Integer
            }), as_list=True)
        }))
    }))
})

_users_fields_get = api.inherit('UsersFieldsGet', users_fields_with_relationships_post_put, {
    'type': fields.String(default='users'),
    'id': fields.Integer,
    'attributes': fields.Nested(users_fields_attributes),
})

_users_fields_post = api.inherit('UsersFieldsPost', users_fields_with_relationships_post_put, {
    'type': fields.String(pattern='users', default='users'),
    'attributes': fields.Nested(users_fields_attributes_post),
})

_users_fields_put = api.inherit('UsersFieldsPut', users_fields_with_relationships_post_put, {
    'type': fields.String(pattern='users', default='users'),
    'attributes': fields.Nested(users_fields_attributes_put),
})


users_fields_get = api.model('UsersRootGet', { 'data': fields.Nested(_users_fields_get) })
users_fields_get_many = api.model('UsersRootGetMany', { 'data': fields.Nested(_users_fields_get, as_list=True) })
users_fields_post = api.model('UsersRootPost', { 'data': fields.Nested(_users_fields_post) })
users_fields_put = api.model('UsersRootPut', { 'data': fields.Nested(_users_fields_put) })
