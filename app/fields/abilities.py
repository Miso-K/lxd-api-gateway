#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_restplus import fields
from app import api

abilities_fields_attributes = api.model('AbilitiesFieldsAttributes', {
    'name': fields.String
})

abilities_fields_with_relationships_put = api.model('AbilitiesFieldsWithRelationshipsPost', {
    'relationships': fields.Nested(api.model('AbilitiesRelationshipsPost', {
        'groups': fields.Nested(api.model('AbilitiesDataPost', {
            'data': fields.Nested(api.model('AbilitiesPostData', {
                'type': fields.String,
                'id': fields.Integer
            }), as_list=True)
        })),
    }))
})

_abilities_fields_get = api.inherit('AbilitiesFieldsGet', abilities_fields_with_relationships_put, {
    'type': fields.String(default='abilities'),
    'id': fields.Integer,
    'attributes': fields.Nested(abilities_fields_attributes),
})

_abilities_fields_put = api.inherit('AbilitiesFieldsPut', abilities_fields_with_relationships_put, {
    'type': fields.String(pattern='abilities', default='abilities'),
})


abilities_fields_get = api.model('AbilitiesRootGet', { 'data': fields.Nested(_abilities_fields_get) })
abilities_fields_get_many = api.model('AbilitiesRootGetMany', { 'data': fields.Nested(_abilities_fields_get, as_list=True) })
abilities_fields_put = api.model('AbilitiesRootPut', { 'data': fields.Nested(_abilities_fields_put) })
