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
#nslxc.add_resource(InstancesStart, '/instances/<int:id>/start')
#nslxc.add_resource(InstancesFreeze, '/instances/<int:id>/freeze')
#nslxc.add_resource(InstancesUnfreeze, '/instances/<int:id>/unfreeze')
#nslxc.add_resource(InstancesStop, '/instances/<int:id>/stop')
#nslxc.add_resource(InstancesRestart, '/instances/<int:id>/restart')
nslxc.add_resource(InstancesExec, '/instances/<int:id>/exec')
nslxc.add_resource(InstancesState, '/instances/<int:id>/state')

# Snapshots routes
nslxc.add_resource(SnapshotsList, '/instances/<int:id>/snapshots')
nslxc.add_resource(Snapshots, '/instances/<int:id>/snapshots/<string:name>')
nslxc.add_resource(SnapshotsRestore, '/instances/<int:id>/snapshots/<string:name>/restore')

# Special and config routes
#nslgw.add_resource(CtsStats, '/stats/<string:server>')
nslgw.add_resource(LgwConfig, '/lxdconfig')
nslgw.add_resource(LxdServersList, '/servers')
nslgw.add_resource(LxdServers, '/servers/<string:name>')
nslgw.add_resource(LxdConfig, '/config/<string:server>')
nslgw.add_resource(RemoteImagesList, '/images/remote')
nslxc.add_resource(Operations, '/operations/<string:server>/<string:id>')

# Networks routes
#nslxc.add_resource(NetworksList, '/networks')

# Profiles routes
#nslxc.add_resource(ProfilesList, '/profiles')
#nslxc.add_resource(Profiles, '/profiles/<string:server>/<string:name>')

# Projects routes
#nslxc.add_resource(ProjectsList, '/projects')
#nslxc.add_resource(Projects, '/projects/<string:server>/<string:name>')

# Images aliases routes
nslxc.add_resource(ImagesList, '/images')
nslxc.add_resource(Images, '/images/<string:server>/<string:fingerprint>')
nslxc.add_resource(ImagesAliasesList, '/images/aliases')
nslxc.add_resource(ImagesAliases, '/images/aliases/<string:server>/<path:alias>')

# Universal lxd routes
nslxc.add_resource(UniversalsList, '/<string:url>')
nslxc.add_resource(Universals, '/<string:url>/<string:server>/<string:name>')

