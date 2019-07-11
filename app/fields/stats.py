#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_restplus import fields
from app import api


cts_stats_fields_attributes = api.model('CtsStats', {
    'containers': fields.Nested(api.model('CtsContainers', {
        'names': fields.List(fields.String),
        'count': fields.Integer,
        'count_running': fields.Integer
    })),
    'cpus': fields.Nested(api.model('CtsCPUs', {
        'cpus_count': fields.Integer,
        'cpus_usage': fields.Integer,
        'processes_count': fields.Integer
    })),
    'memory': fields.Nested(api.model('CtsMemory', {
        'memory_count': fields.String,
        'memory_current_count': fields.Float
    })),
    'disk': fields.Nested(api.model('CtsDisk', {
        'disk_count': fields.Float,
        'disk_usage': fields.Float
    }))
})

_cts_stats_fields_get = api.model('CtsStatsFieldsGet', {
    'type': fields.String(default='stats'),
    'attributes': fields.Nested(cts_stats_fields_attributes),
    'id': fields.Integer(default=1)
})


cts_stats_fields_get = api.model('CtsStatsGet', {'data': fields.Nested(_cts_stats_fields_get)})

