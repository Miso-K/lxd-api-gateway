#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import request
from flask_restplus import Resource
from flask_jwt_extended import fresh_jwt_required, jwt_required, create_access_token, \
    jwt_refresh_token_required, create_refresh_token, get_jti, get_raw_jwt
from .decorators import *
from .fields.containers import *
from .fields.stats import *
from .fields.snapshots import *
from .fields.hosts import *
import lgw
import time


##################
# Containers API #
##################
class ContainersList(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('ct_infos')
    @api.marshal_with(containers_fields_get_many)
    def get(self):
        """
        Get containers list
        :return: containers data
        """
        populate_containers_table()
        current_identity = import_user()
        containers = []

        for c in Container.query.all():
            container = Container.query.filter_by(name=c.name).first()
            if c.id in current_identity.containers or current_identity.admin:
                # containers.append('/api/v1/containers/' + c.name)  # USE THIS LINE FOR QUERY BY NAME
                # containers.append('/api/v1/containers/' + str(c.id))

                container_json = container.__jsonapi__()
                #url = '/api/v1/containers/' + str(i.id)
                #container_json['attributes']['url'] = url

                res = lgw.lxd_api_get('containers/' + c.name)
                container_json['attributes'] = res.json()['metadata']
                res_state = lgw.lxd_api_get('containers/' + c.name + '/state')
                container_json['attributes']['state'] = res_state.json()['metadata']
                containers.append(container_json)

        return {'data': containers}

    @user_has('ct_create')
    #@api.expect(containers_fields_post, validate=True)
    #@api.marshal_with(containers_fields_get)
    @api.doc(responses={
        201: 'Container created',
        409: 'Container already exists',
        500: 'Can\'t create container'
    })
    def post(self):
        """
        Create container based on POST data with image from linuxcontainers.org

        Example:
        data = {'name': 'vpsX', 'source': {'type': 'image', 'mode': 'pull',
            'server': 'https://uk.images.linuxcontainers.org', 'protocol': 'simplestreams',
            'alias': 'ubuntu/16.04'}, 'config': {'limits.cpu': '2', 'limits.memory': '256MB'}}
        :return: status code
        """

        current_identity = import_user()
        data = request.get_json()['data']
        print(data)
        
        if 'name' in data['attributes']:
            c = Container.query.filter_by(name=data['attributes']['name']).first()
            if not c:
                config = {'name': data['attributes']['name'],
                          #'source': {'type': 'image',
                          #           'mode': 'pull',
                          #           'server': 'https://uk.images.linuxcontainers.org',
                          #           'protocol': 'simplestreams',
                          #           'alias': data['attributes']['source']['alias']},
                          'source': data['attributes']['source'],
                          'config': {'limits.cpu': str(data['attributes']['config']['limits_cpu']),
                                     'limits.memory': data['attributes']['config']['limits_memory']}}
                          #'devices': {'root': {'path': '/', 'pool': 'lxd','type': 'disk', 'size': '10GB'}}}
                try:
                    res = lgw.lxd_api_post('containers', data=config)
                    print(res.text)
                except Exception as e:
                    api.abort(code=500, message='Can\'t create container')

                if res.status_code == 202:
                    # Add container to database
                    container = Container(name=data['attributes']['name'])
                    db.session.add(container)
                    db.session.commit()
                    # Get container ID
                    container = Container.query.filter_by(
                        name=data['attributes']['name']).first()
                    # Add container to allowed user's containers
                    user = User.query.get(current_identity.id)
                    user.containers.append(container.id)
                    db.session.commit()
                else:
                    api.abort(code=res.status_code, message='Error when creating container')
                return res.json()
            api.abort(code=409, message='Container already exists')


class Containers(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('ct_infos')
    @api.marshal_with(containers_fields_get)
    def get(self, id):
        """
        Container information
        :param id:
        :return: container data
        """

        populate_containers_table()
        current_identity = import_user()
        try:
            # c = Container.query.filter_by(name=name).first()  # USE FOR QUERY BY NAME
            c = Container.query.filter_by(id=id).first()
            if c and (c.id in current_identity.containers or current_identity.admin):
                res = lgw.lxd_api_get('containers/' + c.name)
                container_json = c.__jsonapi__()
                container_json['attributes'] = res.json()['metadata']
                res_state = lgw.lxd_api_get('containers/' + c.name + '/state')
                container_json['attributes']['state'] = res_state.json()['metadata']

                return {'data': container_json}
            else:
                api.abort(code=403, message='Unauthorized access')
        except KeyError:
            api.abort(code=404, message='Container doesn\'t exists')


    @user_has('ct_update')
    @api.expect(containers_fields_put, validate=True)
    @api.marshal_with(containers_fields_put)
    @api.doc(responses={
        200: 'Container config changed',
        404: 'Container doesn\'t exists',
        500: 'Can\'t update container config'
    })
    def put(self, id, d=None):
        """
        Change container name and config
        # use patch instead of put to set only selected config
        :param id:
        :param d:
        :return: container data
        """

        if d:
            data = d
        else:
            data = request.get_json()['data']

        current_identity = import_user()

        try:
            c = Container.query.get(id)
        except:
            api.abort(code=404, message='Container doesn\'t exists')
        if c.name and (id in current_identity.containers or current_identity.admin):
            if 'limits_cpu' in data['attributes']['config']:
                config = {
                          'config': {'limits.cpu': str(data['attributes']['config']['limits_cpu'])}}
                try:
                    res = lgw.lxd_api_patch('containers/'+c.name, data=config)
                    print(res.text)
                except Exception as e:
                    api.abort(code=500, message='Can\'t create container')
            if 'limits_memory' in data['attributes']['config']:
                config = {
                    'config': {'limits.memory': data['attributes']['config']['limits_memory']}}
                try:
                    res = lgw.lxd_api_patch('containers/'+c.name, data=config)
                    print(res.text)
                except Exception as e:
                    api.abort(code=500, message='Can\'t create container')

        else:
            api.abort(code=404, message='Container doesn\'t exists')

        return {'data': data}

    @user_has('ct_delete')
    @api.doc(responses={
        204: 'Container deleted',
        400: 'Container is running',
        404: 'Container doesn\'t exists'
    })
    def delete(self, id):
        """
        Delete container
        :param id:
        :return status code
        """

        populate_containers_table()
        current_identity = import_user()

        try:
            c = Container.query.get(id)
            print(c)
        except:
            api.abort(code=404, message='Container doesn\'t exists')

        if id in current_identity.containers or current_identity.admin:
            res = lgw.lxd_api_delete('containers/' + c.name)
            print(res.text)
            if res.status_code == 400:
                api.abort(code=400, message='Container is running')
            if res.status_code == 404:
                api.abort(code=404, message='Container not found')
            if res.status_code == 202:
                db.session.delete(c)
                db.session.commit()
                return {}, 204
        else:
            api.abort(code=404, message='Container not found')


class ContainersState(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('ct_infos')
    #@api.marshal_with(containers_fields_get)
    def get(self, id):
        """
        Container state information
        :param id:
        :return container data
        """

        populate_containers_table()
        current_identity = import_user()
        try:
            # c = Container.query.filter_by(name=name).first()  # USE FOR QUERY BY NAME
            c = Container.query.filter_by(id=id).first()
            if c and (c.id in current_identity.containers or current_identity.admin):
                res = lgw.lxd_api_get('containers/' + c.name + '/state')
                return res.json()
            else:
                api.abort(code=403, message='Unauthorized access')
        except:
            api.abort(code=404, message='Container doesn\'t exists')


class ContainersStart(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('ct_start')
    @api.doc(responses={
        200: 'Container started',
        404: 'Container doesn\'t exists',
        403: 'Start timed out'
    })
    def post(self, id):
        """
        Start container
        :param id:
        :return status code
        """

        data = {
            'action': 'start',
            'timeout': 30
        }

        current_identity = import_user()
        try:
            # c = Container.query.filter_by(name=name).first()  # USE FOR QUERY BY NAME
            c = Container.query.filter_by(id=id).first()
            if c and (c.id in current_identity.containers or current_identity.admin):
                res = lgw.lxd_api_put('containers/' + c.name + '/state', data)
                return res.json()
            else:
                api.abort(code=403, message='Unauthorized access')
        except:
            api.abort(code=404, message='Container doesn\'t exists')


class ContainersFreeze(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('ct_freeze')
    @api.doc(responses={
        204: 'Container frozen',
        404: 'Container doesn\'t exists',
        500: 'Freeze timed out'
    })
    def post(self, id):
        """
        Freeze container
        :param id:
        :return data
        """
        data = {
            'action': 'freeze',
            'timeout': 30
        }

        current_identity = import_user()
        try:
            # c = Container.query.filter_by(name=name).first()  # USE FOR QUERY BY NAME
            c = Container.query.filter_by(id=id).first()
            if c and (c.id in current_identity.containers or current_identity.admin):
                res = lgw.lxd_api_put('containers/' + c.name + '/state', data)
                return res.json()
            else:
                api.abort(code=403, message='Unauthorized access')
        except:
            api.abort(code=404, message='Container doesn\'t exists')


class ContainersUnfreeze(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('ct_unfreeze')
    @api.doc(responses={
        204: 'Container thawed',
        404: 'Container doesn\'t exists',
        500: 'Unfreeze timed out'
    })
    def post(self, id):
        """
        Unfreeze container
        :param id
        :return data
        """
        data = {
            'action': 'unfreeze',
            'timeout': 30
        }

        current_identity = import_user()
        try:
            # c = Container.query.filter_by(name=name).first()  # USE FOR QUERY BY NAME
            c = Container.query.filter_by(id=id).first()
            if c and (c.id in current_identity.containers or current_identity.admin):
                res = lgw.lxd_api_put('containers/' + c.name + '/state', data)
                return res.json()
            else:
                api.abort(code=403, message='Unauthorized access')
        except:
            api.abort(code=404, message='Container doesn\'t exists')


class ContainersStop(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('ct_stop')
    @api.doc(responses={
        204: 'Container stopped',
        404: 'Container doesn\'t exists',
        500: 'Stop timed out'
    })
    def post(self, id):
        """
        Stop container
        :param id:
        :return data
        """
        data = {
            'action': 'stop',
            'timeout': 30
        }

        current_identity = import_user()
        try:
            # c = Container.query.filter_by(name=name).first()  # USE FOR QUERY BY NAME
            c = Container.query.filter_by(id=id).first()
            if c and (c.id in current_identity.containers or current_identity.admin):
                res = lgw.lxd_api_put('containers/' + c.name + '/state', data)
                return res.json()
            else:
                api.abort(code=403, message='Unauthorized access')
        except:
            api.abort(code=404, message='Container doesn\'t exists')


class ContainersStopForce(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('ct_stop')
    @api.doc(responses={
        204: 'Container stopped',
        404: 'Container doesn\'t exists',
        500: 'Stop timed out'
    })
    def post(self, id):
        """
        Stop container
        :param id:
        :return data
        """
        data = {
            'action': 'stop',
            'timeout': 30,
            'force': True
        }

        current_identity = import_user()
        try:
            # c = Container.query.filter_by(name=name).first()  # USE FOR QUERY BY NAME
            c = Container.query.filter_by(id=id).first()
            if c and (c.id in current_identity.containers or current_identity.admin):
                res = lgw.lxd_api_put('containers/' + c.name + '/state', data)
                return res.json()
            else:
                api.abort(code=403, message='Unauthorized access')
        except:
            api.abort(code=404, message='Container doesn\'t exists')


class ContainersRestart(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('ct_restart')
    @api.doc(responses={
        204: 'Container restarted',
        404: 'Container doesn\'t exists',
        500: 'Restart timed out'
    })
    def post(self, id):
        """
        Restart container
        :param id:
        :return data
        """
        data = {
            'action': 'restart',
            'timeout': 30
        }

        current_identity = import_user()
        try:
            # c = Container.query.filter_by(name=name).first()  # USE FOR QUERY BY NAME
            c = Container.query.filter_by(id=id).first()
            if c and (c.id in current_identity.containers or current_identity.admin):
                res = lgw.lxd_api_put('containers/' + c.name + '/state', data)
                return res.json()
            else:
                api.abort(code=403, message='Unauthorized access')
        except:
            api.abort(code=404, message='Container doesn\'t exists')


class ContainersExec(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('ct_terminal')
    def post(self, id):
        """
        Open container terminal
        :param id
        :return terminal data
        """
        # this part working for /exec api
        data = {
            'command': ['/bin/bash'],       # Command and arguments
            'environment': {},              # Optional extra environment variables to set
            'wait-for-websocket': True,    # Whether to wait for a connection before starting the process
            'record-output': False,         # Whether to store stdout and stderr (only valid with wait-for-websocket=false) (requires API extension container_exec_recording)
            'interactive': True,            # Whether to allocate a pts device instead of PIPEs
            'width': 80,                    # Initial width of the terminal (optional)
            'height': 25,                   # Initial height of the terminal (optional)
        }
        # this part working for /console api
        # data = {
        #    'width': 80,
        #    'height': 25
        # }

        current_identity = import_user()
        try:
            # c = Container.query.filter_by(name=name).first()  # USE FOR QUERY BY NAME
            c = Container.query.filter_by(id=id).first()
            if c and (c.id in current_identity.containers or current_identity.admin):
                res = lgw.lxd_api_post('containers/' + c.name + '/exec', data)
                # return res.json()
                return {'data': {'type': 'terminal', 'id': id, 'attributes': res.json()}}, 201
            else:
                api.abort(code=403, message='Unauthorized access')
        except:
            api.abort(code=404, message='Container doesn\'t exists')


##################
# Snapshots API #   NEED TO WORK / ZFS LXD
##################


class SnapshotsList(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('snapshot_infos')
    @api.marshal_with(snapshots_fields_get_many)
    def get(self, id):
        """
        Get snapshot list
        """
        current_identity = import_user()
        container = Container.query.get(id)
        snapshots = []
        
        #If exists
        client = lgw.lxd_client()
        c = client.containers.get(container.name)

        if c.name and (id in current_identity.containers or current_identity.admin):
            all = c.snapshots.all()
            for snap in all:
                snapshot_json = {'attributes': {'name': snap.name, 'created_at': snap.created_at,
                                                'stateful': snap.stateful}}
                snapshots.append(snapshot_json)
                
        return {'data': snapshots}

    @user_has('snapshot_create')
    @api.expect(snapshots_fields_post, validate=True)
    @api.marshal_with(snapshots_fields_get)
    @api.doc(responses={
        201: 'Snapshot created',
        409: 'Snapshot already exists',
        500: 'Can\'t create snapshot'
    })
    def post(self, id):
        """
        Create snapshot
        """
        data = request.get_json()['data']

        current_identity = import_user()
        container = Container.query.get(id)

        # If exists
        client = lgw.lxd_client()
        c = client.containers.get(container.name)

        if c.name and (id in current_identity.containers or current_identity.admin):
            snapname = data['attributes']['name']
            if not c.snapshots.create(snapname):
                api.abort(code=409, message='Snapshot name already exists')
            else:
                time.sleep(20)
                snap = c.snapshots.get(snapname)
                snapshot_json = {
                    'attributes': {'name': snap.name, 'created_at': snap.created_at, 'stateful': snap.stateful}}

                return {'data': snapshot_json}

        api.abort(code=500, message='Can\'t create container')


class Snapshots(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('snapshot_infos')
    @api.marshal_with(snapshots_fields_get)
    def get(self, id, name):
        """
        Get snapshot
        """
        current_identity = import_user()
        container = Container.query.get(id)

        #If exists
        client = lgw.lxd_client()
        c = client.containers.get(container.name)

        if c.name and (id in current_identity.containers or current_identity.admin):
            try:
                snap = c.snapshots.get(name)
                snapshot_json = {'attributes': {'name': snap.name, 'created_at': snap.created_at, 'stateful': snap.stateful }}
            except:
                api.abort(code=404, message='Snapshot doesn\'t exists')
                
            return {'data': snapshot_json}
        api.abort(code=404, message='Container doesn\'t exists')

    @user_has('snapshot_rename')
    @api.expect(snapshots_fields_put, validate=True)
    @api.marshal_with(snapshots_fields_get)
    def put(self, id, name, d=None):
        """
        Update snapshot
        """
        client = lgw.lxd_client()
        if d:
            data = d
        else:
            data = request.get_json()['data']

        current_identity = import_user()
        container = Container.query.get(id)

        c = client.containers.get(container.name)

        if c.name and (id in current_identity.containers or current_identity.admin):
            if 'name' in data['attributes']:
                try:
                    snap = c.snapshots.get(name)
                except:
                    api.abort(code=404, message='Snapshot doesn\'t exists')
                if name == snap.name:
                    snap.rename(data['attributes']['name'])
                else:
                    api.abort(
                        code=500, message='Error while rename snapshot')

            snapshot_json = {
                'attributes': {'name': snap.name, 'created_at': snap.created_at, 'stateful': snap.stateful}}

            return {'data': snapshot_json}
        api.abort(code=404, message='Container doesn\'t exists')
        
    @user_has('snapshot_delete')
    def delete(self, id, name):
        """
        Delete snapshot
        """
        current_identity = import_user()
        container = Container.query.get(id)
        client = lgw.lxd_client()
        c = client.containers.get(container.name)

        if c.name and (id in current_identity.containers or current_identity.admin):
            try:
                if name == c.snapshots.get(name).name:
                    try:
                        c.snapshots.get(name).delete()
                        time.sleep(5)
                        return {}, 204
                    except:
                        api.abort(code=500, message='Error deleting snapshot')
            except:
                api.abort(code=404, message='Snapshot doesn\'t exists')

        api.abort(code=404, message='Container doesn\'t exists')


class SnapshotsRestore(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('snapshot_restore')
    @api.doc(responses={
        204: 'Snapshot restored',
        404: 'Snapshot doesn\'t exists',
        500: 'Snapshot timed out'
    })
    def post(self, id, name):
        """
        Restore snapshot
        """
        current_identity = import_user()
        container = Container.query.get(id)
        client = lgw.lxd_client()
        c = client.containers.get(container.name)

        if c.name and (id in current_identity.containers or current_identity.admin):
            try:
                if name == c.snapshots.get(name).name:
                    try:
                        c.raw_put({'restore': name})
                        time.sleep(20)
                        return {}, 204
                    except:
                        api.abort(code=500, message='Error restoring snapshot')
            except:
                api.abort(code=404, message='Snapshot doesn\'t exists')

        api.abort(code=404, message='Container doesn\'t exists')
        
##################
# Other API #
##################


class LxcHostResources(Resource):
    decorators = [jwt_required, otp_confirmed]

    @api.marshal_with(cts_hosts_fields_get)
    @user_has('lxc_infos')
    def get(self):
        """
        Get lxd host resources
        :return data
        """

        json_output = lgw.lxd_api_get('resources').json()['metadata']
        return {'data': {'attributes': json_output}}


class LxcCheckConfig(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('lxc_infos')
    def get(self):
        """
        Check LXC configuration (lxc-checkconfig)
        :return data
        """
        conf = lgw.lxd_api_get_config().json()['metadata']
        return {'data': conf}

        
class CtsStats(Resource):
    decorators = [jwt_required, otp_confirmed]

    @api.marshal_with(cts_stats_fields_get)
    @user_has('cts_stats')
    def get(self):
        """
        Containers stats resources
        :return data
        """

        populate_containers_table()
        current_identity = import_user()
        alist = []

        all = []
        res = lgw.lxd_api_get('containers')
        for c in res.json()['metadata']:
            all.append(c[16:])

        for ct in all:
            container = Container.query.filter_by(name=ct).first()
            if container.id in current_identity.containers or current_identity.admin:
                alist.append(ct)

        json_output = lgw.cts_stats(alist)
        return {'data': {'attributes': json_output}}

