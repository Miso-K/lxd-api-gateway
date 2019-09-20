#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_restplus import fields
from app import api

# need to change
lxd_container_resources = api.model('LxdContainerResources', {
    'processes': fields.Integer(default=0),
    'cpu_usage': fields.Nested(api.model('LxcCpuUsage', {
            'cpu_seconds': fields.Integer(default=0)
        })),
    'memory_usage': fields.Nested(api.model('LxcMemoryUsage', {
            'memory_current': fields.Integer(default=0),
            'memory_peak': fields.Integer(default=0)
        })),    
    'network_usage': fields.Nested(api.model('LxcNetworkUsage', {
            'eth0': fields.Nested(api.model('LxcNetworkEth0Usage', {
                'bytes_received': fields.Integer(default=0),
                'bytes_sent': fields.Integer(default=0),
                'packets_received': fields.Integer(default=0),
                'packets_sent': fields.Integer(default=0)
            }))
        })),
    'disk_usage': fields.Nested(api.model('LxcDiskUsage', {
            'root': fields.Integer(default=0)
        }))
})

lxd_container_config = api.model('LxdContainerConfig', {
    'limits_cpu': fields.String(default=None),
    'limits_memory': fields.String(default=None),
    'limits_memory_raw': fields.String(default=None),
    'limits_disk': fields.String(default=None),
    'limits_disk_raw': fields.String(default=None),
    'image_architecture': fields.String,
    'image_description': fields.String,
    'image_os': fields.String,
    'image_release': fields.String,
    'image_version': fields.String
})

containers_fields_attributes = api.model('ContainersFieldsAttributes', {
    'name': fields.String,
    'created': fields.String,
    'status': fields.String,
    'pid': fields.Integer,
    #'ips': fields.Raw, # need to change
    #'ips': fields.Nested(api.model('ContainersIps', {
    #            'netmask': fields.Integer(default=0),
    #            'family': fields.String(default=None),
    #            'scope': fields.String(default=None),
    #            'address': fields.String(default=None)
    #        }), as_list=True),
    #'resources': fields.Nested(lxd_container_resources),
    'config': fields.Nested(lxd_container_config),
    'state': fields.Raw()
})

#require MB in memory string
lxd_container_config_post = api.model('LxdContainerConfig', {
    'limits_cpu': fields.String(default=None, pattern='^([0-9])*$'),
    'limits_memory': fields.String(default=None, pattern='^([0-9]*MB|GB)*$'),
    'limits_disk': fields.String(default=None, pattern='^([0-9]*MB|GB)*$')
})

containers_fields_attributes_post = api.model('ContainersFieldsAttributesPost', {
    'name': fields.String(required=True, pattern='^(?!\s*$).+'),
    'source': fields.Nested(api.model('ContainersSourcePost', {
        'type': fields.String(default='image'),
        'alias': fields.String(required=True, pattern='^(?!\s*$).+', default='ubuntu/xenial')
    })),
    'config': fields.Nested(lxd_container_config_post)
})

containers_fields_attributes_put = api.model('ContainersFieldsAttributesPut', {
    'name': fields.String,
    'config': fields.Raw,
    'devices': fields.Raw
})

containers_fields_with_relationships_post_put = api.model('ContainersFieldsWithRelationshipsPost', {
    'relationships': fields.Nested(api.model('ContainersRelationshipsPost', {
        'users': fields.Nested(api.model('ContainersDataPost', {
            'data': fields.Nested(api.model('ContainersPostData', {
                'type': fields.String(default='users'),
                'id': fields.Integer
            }), as_list=True)
        })),
    }))
})

_containers_fields_get = api.inherit('ContainersFieldsGet', containers_fields_with_relationships_post_put, {
    'type': fields.String(default='containers'),
    'id': fields.Integer,
    #'attributes': fields.Nested(containers_fields_attributes),
    'attributes': fields.Raw()
})

_containers_fields_post = api.inherit('ContainersFieldsPost', containers_fields_with_relationships_post_put, {
    'type': fields.String(pattern='containers', default='containers'),
    'attributes': fields.Nested(containers_fields_attributes_post),
})

_containers_fields_put = api.inherit('ContainersFieldsPut', containers_fields_with_relationships_post_put, {
    'type': fields.String(pattern='containers', default='containers'),
    'attributes': fields.Nested(containers_fields_attributes_put),
})


containers_fields_get = api.model('ContainersRootGet', { 'data': fields.Nested(_containers_fields_get) })
containers_fields_get_many = api.model('ContainersRootGetMany', { 'data': fields.Nested(_containers_fields_get, as_list=True) })
containers_fields_post = api.model('ContainersRootPost', { 'data': fields.Nested(_containers_fields_post) })
containers_fields_put = api.model('ContainersRootPut', { 'data': fields.Nested(_containers_fields_put) })
