#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_restplus import fields
from app import api

requests_fields_get = api.model('RequestGet', { 'status': fields.String })
requests_fields_post = api.model('RequestPost', {
    'subject': fields.String(required=True),
    'message': fields.String(required=True),
    'copy': fields.Boolean(default=False)
    }
)
