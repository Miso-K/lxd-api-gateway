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

# Containers routes
nslxc.add_resource(ContainersList, '/containers')
nslxc.add_resource(Containers, '/containers/<int:id>')
nslxc.add_resource(ContainersStart, '/containers/<int:id>/start')
nslxc.add_resource(ContainersFreeze, '/containers/<int:id>/freeze')
nslxc.add_resource(ContainersUnfreeze, '/containers/<int:id>/unfreeze')
nslxc.add_resource(ContainersStop, '/containers/<int:id>/stop')
nslxc.add_resource(ContainersRestart, '/containers/<int:id>/restart')
nslxc.add_resource(ContainersExec, '/containers/<int:id>/exec')
nslxc.add_resource(ContainersState, '/containers/<int:id>/state')

# Special and config routes
nslgw.add_resource(CtsStats, '/stats')
nslgw.add_resource(UsersRequest, '/request')
nslgw.add_resource(LXDConfig, '/lxdconfig')
nslgw.add_resource(LXDCerts, '/lxdcerts')
nslxc.add_resource(LxcHostResources, '/resources')
nslxc.add_resource(LxcCheckConfig, '/checkconfig')

# Snapshots routes - not tested for production
# nslxc.add_resource(SnapshotsList, '/containers/<string:name>/snapshots')
# nslxc.add_resource(Snapshots, '/containers/<string:name>/snapshots/<string:sname>')
# nslxc.add_resource(SnapshotsRestore, '/containers/<string:name>/snapshots/<string:sname>/restore')
