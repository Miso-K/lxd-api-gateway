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
    'limits_cpu': fields.Raw(default=None),
    'limits_memory': fields.String(default=None, pattern='^([0-9]*MB|[0-9]*GB)*$'),
    'limits_disk': fields.String(default=None, pattern='^([0-9]*MB|[0-9]*GB)*$')
})

# copy not working when uncomment
containers_fields_attributes_post = api.model('ContainersFieldsAttributesPost', {
    'name': fields.String(required=True, pattern='^(?!\s*$).+'),
    'source': fields.Raw,
    #'source': fields.Nested(api.model('ContainersSourcePost', {
    #    'type': fields.String(default=None),
    #    'alias': fields.String(pattern='^(?!\s*$).+', default=None),
    #    'mode': fields.String(default=None),
    #    'server': fields.String(default=None),
    #    'protocol': fields.String(default=None),
    #    'container_only': fields.Raw(default=None),
    #    'source': fields.String(default=None)
    #})),
    #'config': fields.Nested(lxd_container_config_post)
    'config': fields.Raw
})

containers_fields_attributes_put = api.model('ContainersFieldsAttributesPut', {
    'name': fields.String,
    'config': fields.Raw,
    'devices': fields.Raw
})

containers_fields_with_relationships_post_put = api.model('ContainersFieldsWithRelationshipsPost', {
    'relationships': fields.Nested(api.model('ContainersRelationshipsPost', {
        'users': fields.Nested(api.model('ContainersDataPost', {
            'type': fields.String(default='users'),
            'id': fields.Integer
        }), as_list=True)
    }))
})

_containers_fields_get = api.inherit('ContainersFieldsGet', containers_fields_with_relationships_post_put, {
    'type': fields.String(default='containers'),
    'id': fields.Integer,
    #'attributes': fields.Nested(containers_fields_attributes),
    'attributes': fields.Raw(),
    'architecture': fields.Raw(),
    'config': fields.Raw(),
    'devices': fields.Raw(),
    'ephemeral': fields.Raw(),
    'profiles': fields.Raw(),
    'stateful': fields.Raw(),
    'description': fields.Raw(),
    'created_at': fields.Raw(),
    'expanded_config': fields.Raw(),
    'expanded_devices': fields.Raw(),
    'name': fields.Raw(),
    'status': fields.Raw(),
    'status_code': fields.Raw(),
    'last_used_at': fields.Raw(),
    'location': fields.Raw(),
    'type': fields.Raw(),
    'state': fields.Raw(),
    'pid': fields.Raw(),
    'processes': fields.Raw(),
    'cpu': fields.Raw()
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

containers_fields_get_many2 = api.model('ContainersRootGetMany', { 'data': fields.Raw })