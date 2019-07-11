#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_restplus import fields
from app import api


_cts_host_fields_get = api.model('HostStatsFieldsGet', {
    'type': fields.String(default='host'),
    'attributes': fields.Raw(),
    'id': fields.Integer(default=1)
})


cts_hosts_fields_get = api.model('HostStatsRootGet', {'data': fields.Nested(_cts_host_fields_get)})
