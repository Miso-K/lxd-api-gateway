#!/usr/bin/env python
# -*- coding: utf-8 -*-
from app import auth, nslxc, nslgw
from .views import *
from .views_lxd import *

# Auth routes
auth.add_resource(Auth, '/auth')
auth.add_resource(AuthOtp, '/auth/otp')
auth.add_resource(AuthRefresh, '/auth/refresh')
auth.add_resource(AuthCheck, '/auth/check')
auth.add_resource(AuthLogout, '/auth/logout')

# Users routes
nslgw.add_resource(UsersList, '/users')
nslgw.add_resource(Users, '/users/<int:id>')
nslgw.add_resource(Me, '/me')
nslgw.add_resource(MeOtp, '/me/otp')
nslgw.add_resource(GroupsList, '/groups')
nslgw.add_resource(Groups, '/groups/<int:id>')
nslgw.add_resource(AbilitiesList, '/abilities')
nslgw.add_resource(Abilities, '/abilities/<int:id>')
nslgw.add_resource(RequestsList, '/requests')
nslgw.add_resource(Requests, '/requests/<int:id>')

# Instances routes
nslxc.add_resource(InstancesList, '/instances')
nslxc.add_resource(Instances, '/instances/<int:id>')
nslxc.add_resource(InstancesStart, '/instances/<int:id>/start')
nslxc.add_resource(InstancesFreeze, '/instances/<int:id>/freeze')
nslxc.add_resource(InstancesUnfreeze, '/instances/<int:id>/unfreeze')
nslxc.add_resource(InstancesStop, '/instances/<int:id>/stop')
nslxc.add_resource(InstancesRestart, '/instances/<int:id>/restart')
nslxc.add_resource(InstancesExec, '/instances/<int:id>/exec')
nslxc.add_resource(InstancesState, '/instances/<int:id>/state')

# Special and config routes
nslxc.add_resource(Operations, '/operations/<string:id>')
nslgw.add_resource(CtsStats, '/stats')
nslgw.add_resource(LXDConfig, '/lxdconfig')
nslgw.add_resource(LXDCerts, '/lxdcerts')
nslxc.add_resource(LxcHostResources, '/resources')
nslxc.add_resource(LxcCheckConfig, '/checkconfig')

# Snapshots routes
nslxc.add_resource(SnapshotsList, '/instances/<int:id>/snapshots')
nslxc.add_resource(Snapshots, '/instances/<int:id>/snapshots/<string:name>')
nslxc.add_resource(SnapshotsRestore, '/instances/<int:id>/snapshots/<string:name>/restore')

# Images routes
nslxc.add_resource(ImagesList, '/images')
nslxc.add_resource(Images, '/images/<string:fingerprint>')
nslxc.add_resource(ImagesAliasesList, '/images/aliases')
nslxc.add_resource(ImagesAliases, '/images/aliases/<path:alias>')
nslxc.add_resource(RemoteImagesList, '/images/remote')

# Networks routes
nslxc.add_resource(NetworksList, '/networks')

# Profiles routes
nslxc.add_resource(ProfilesList, '/profiles')
nslxc.add_resource(Profiles, '/profiles/<string:name>')

# Projects routes
nslxc.add_resource(ProjectsList, '/projects')
nslxc.add_resource(Projects, '/projects/<string:name>')