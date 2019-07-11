#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_restplus import fields
from app import api

auth_fields_get = api.model('AuthGet', {
    'access_token': fields.String,
    'refresh_token': fields.String
    }
)
auth_fields_post = api.model('AuthPost', {
    'username': fields.String(required=True),
    'password': fields.String(required=True)
    }
)

auth_otp_fields_get = api.model('AuthOtpGet', {
    'access_token': fields.String,
    'refresh_token': fields.String
    }
)
auth_otp_fields_post = api.model('AuthOtpPost', {
    'secret': fields.String(required=True)
    }
)
