#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import request
from flask_restplus import Resource
from flask_jwt_extended import jwt_required
from .decorators import *
from .fields.instances import *
from .fields.stats import *
from .fields.snapshots import *
from .fields.hosts import *
from app import redis_store
import lgw
import json
# import time

##################
# Instances API #
##################


class InstancesList(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('instances_infos_all')
    @api.marshal_with(instances_fields_get_many)
    def get(self):
        """
        Get instances list
        :return: instances data
        """
        populate_instances_table()
        current_identity = import_user()
        instances = []

        # starttime = time.time()
        for c in Instance.query.all():
            instance = Instance.query.filter_by(name=c.name).first()
            if c.id in current_identity.instances or current_identity.admin:
                instance_json = instance.__jsonapi__()

                try:
                    instance_json.update(json.loads(redis_store.get('instances:'+c.name+':info')))
                    instance_json['state'] = (json.loads(redis_store.get('instances:' + c.name + ':state')))
                except TypeError:
                    res = lgw.lxd_api_get('instances/' + c.name)
                    instance_json.update(res.json()['metadata'])
                    res_state = lgw.lxd_api_get('instances/' + c.name + '/state')
                    instance_json['state'] = res_state.json()['metadata']

                instances.append(instance_json)

        # print('time: ', time.time() - starttime)
        return {'data': instances}

    @user_has('instances_create')
    @api.expect(instances_fields_post, validate=False)
    # @api.marshal_with(instances_fields_get)
    @api.doc(responses={
        201: 'Instance created',
        409: 'Instance already exists',
        500: 'Can\'t create instance'
    })
    def post(self):
        """
        Create instance based on POST data with image from linuxcontainers.org

        :return: status code
        """

        current_identity = import_user()
        data = request.get_json()['data']
        # print(data)
        
        if 'name' in data:
            c = Instance.query.filter_by(name=data['name']).first()
            if not c:
                config = data['instance']
                # if not admin, recalculate price
                # if 'user.price' in config['config']:
                #    config['config']['user.price'] = '5'
                # print('Config2', config)
                try:
                    res = lgw.lxd_api_post('instances', data=config)
                    print(res.text)
                    print(res.status_code)
                except Exception as e:
                    api.abort(code=500, message='Can\'t create instance')

                if res.status_code == 202:
                    # Add instance to database
                    instance = Instance(name=data['name'])
                    db.session.add(instance)
                    db.session.commit()
                    # Get instance ID
                    instance = Instance.query.filter_by(
                        name=data['name']).first()
                    # Add instance to allowed users
                    if current_identity.admin:
                        try:
                            users_id = list(id['id'] for id in data['relationships']['users'])
                            for user_id in users_id:
                                user = User.query.get(user_id)
                                user.instances.append(instance.id)
                                db.session.commit()
                        except KeyError:
                            pass
                        except AttributeError:
                            api.abort(code=500, message='User doesn\'t exists')
                    # Add instance to current user
                    else:
                        user = User.query.get(current_identity.id)
                        user.instances.append(instance.id)
                        db.session.commit()
                else:
                    api.abort(code=res.status_code, message='Error when creating instance')

                # instance_json = instance.__jsonapi__()
                # return {'data': instance_json}
                return res.json()
            api.abort(code=409, message='Instance already exists')


class Instances(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('instances_infos')
    @api.marshal_with(instances_fields_get)
    def get(self, id):
        """
        Instance information
        :param id:
        :return: instance data
        """

        populate_instances_table()
        current_identity = import_user()
        try:
            # c = Instance.query.filter_by(name=name).first()  # USE FOR QUERY BY NAME
            c = Instance.query.filter_by(id=id).first()
            if c and (c.id in current_identity.instances or current_identity.admin):
                res = lgw.lxd_api_get('instances/' + c.name)
                instance_json = c.__jsonapi__()
                instance_json.update(res.json()['metadata'])
                res_state = lgw.lxd_api_get('instances/' + c.name + '/state')
                instance_json['state'] = res_state.json()['metadata']

                # update redis data about instance
                redis_store.set('instances:' + c.name + ':info', json.dumps(res.json()['metadata']))
                redis_store.set('instances:' + c.name + ':state', json.dumps(res_state.json()['metadata']))

                return {'data': instance_json}
            else:
                api.abort(code=403, message='Unauthorized access')
        except KeyError:
            api.abort(code=404, message='Instance doesn\'t exists')

    @user_has('instances_update')
    @api.expect(instances_fields_put, validate=True)
    @api.marshal_with(instances_fields_put)
    @api.doc(responses={
        200: 'Instance config changed',
        404: 'Instance doesn\'t exists',
        500: 'Can\'t update instance config'
    })
    def put(self, id, d=None):
        """
        Change instance name and config
        # use patch instead of put to set only selected config
        :param id:
        :param d:
        :return: instance data
        """

        if d:
            data = d
        else:
            data = request.get_json()['data']

        current_identity = import_user()

        try:
            c = Instance.query.get(id)
            if c.name and (id in current_identity.instances or current_identity.admin):
                if 'limits_cpu' in data['config']:
                    config = {
                              'config': {'limits.cpu': str(data['config']['limits_cpu'])}}
                    try:
                        res = lgw.lxd_api_patch('instances/'+c.name, data=config)
                        # print(res.text)
                    except Exception as e:
                        api.abort(code=500, message='Can\'t create instance')
                if 'limits_memory' in data['config']:
                    config = {
                        'config': {'limits.memory': data['config']['limits_memory']}}
                    try:
                        res = lgw.lxd_api_patch('instances/'+c.name, data=config)
                        # print(res.text)
                    except Exception as e:
                        api.abort(code=500, message='Can\'t create instance')

                # Delete redis cache
                redis_store.delete('instances:' + c.name + ':info')
                redis_store.delete('instances:' + c.name + ':state')

            else:
                api.abort(code=404, message='Instance doesn\'t exists')
        except:
            api.abort(code=404, message='Instance doesn\'t exists')

        return {'data': data}

    @user_has('instances_update')
    @api.expect(instances_fields_put, validate=True)
    @api.marshal_with(instances_fields_put)
    @api.doc(responses={
        200: 'Instance config changed',
        404: 'Instance doesn\'t exists',
        500: 'Can\'t update instance config'
    })
    def patch(self, id, d=None):
        """
        Change instance name and config
        # use patch instead of put to set only selected config
        :param id:
        :param d:
        :return: instance data
        """

        if d:
            data = d
        else:
            data = request.get_json()['data']

        current_identity = import_user()

        try:
            c = Instance.query.get(id)
            if c.name and (id in current_identity.instances or current_identity.admin):
                config = data['instance']
                try:
                    res = lgw.lxd_api_patch('instances/' + c.name, data=config)
                    print(res.text)
                    print(res.status_code)
                    if res.status_code == 500:
                        api.abort(code=500, message='Can\'t create instance')
                except Exception as e:
                    api.abort(code=500, message='Can\'t create instance')

                # Delete redis cache
                redis_store.delete('instances:' + c.name + ':info')
                redis_store.delete('instances:' + c.name + ':state')

            else:
                api.abort(code=404, message='Instance doesn\'t exists')
        except:
            api.abort(code=404, message='Instance doesn\'t exists')

        return {'data': data}

    @user_has('instances_delete')
    @api.doc(responses={
        204: 'Instance deleted',
        400: 'Instance is running',
        404: 'Instance doesn\'t exists'
    })
    def delete(self, id):
        """
        Delete instance
        :param id:
        :return status code
        """

        populate_instances_table()
        current_identity = import_user()

        try:
            c = Instance.query.get(id)
            # print(c)
        except:
            api.abort(code=404, message='Instance doesn\'t exists')

        if id in current_identity.instances or current_identity.admin:
            res = lgw.lxd_api_delete('instances/' + c.name)
            # print(res.status_code)
            if res.status_code == 400:
                api.abort(code=404, message='Instance is running')
            if res.status_code == 404:
                api.abort(code=404, message='Instance not found')
            if res.status_code == 202:
                db.session.delete(c)
                db.session.commit()
                return {}, 204

            # Delete redis cache
            redis_store.delete('instances:' + c.name + ':info')
            redis_store.delete('instances:' + c.name + ':state')

        else:
            api.abort(code=404, message='Instance not found')


class InstancesState(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('instances_state_infos')
    # @api.marshal_with(instances_fields_get)
    def get(self, id):
        """
        Instance state information
        :param id:
        :return instance data
        """

        populate_instances_table()
        current_identity = import_user()
        try:
            # c = Instance.query.filter_by(name=name).first()  # USE FOR QUERY BY NAME
            c = Instance.query.filter_by(id=id).first()
            if c and (c.id in current_identity.instances or current_identity.admin):
                res = lgw.lxd_api_get('instances/' + c.name + '/state')
                return {'data': res.json()}
            else:
                api.abort(code=403, message='Unauthorized access')
        except:
            api.abort(code=404, message='Instance doesn\'t exists')

    @user_has('instances_state_update')
    def put(self, id, d=None):
        """
        :return
        """
        if d:
            data = d
        else:
            data = request.get_json()['data']

        current_identity = import_user()
        try:
            # c = Instance.query.filter_by(name=name).first()  # USE FOR QUERY BY NAME
            c = Instance.query.filter_by(id=id).first()
            if c and (c.id in current_identity.instances or current_identity.admin):
                res = lgw.lxd_api_put('instances/' + c.name + '/state', data)

                # Delete redis cache
                redis_store.delete('instances:' + c.name + ':info')
                redis_store.delete('instances:' + c.name + ':state')

                return {'data': res.json()}
            else:
                api.abort(code=403, message='Unauthorized access')
        except:
            api.abort(code=404, message='Instance doesn\'t exists')


class InstancesStart(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('instances_start')
    @api.doc(responses={
        200: 'Instance started',
        404: 'Instance doesn\'t exists',
        403: 'Start timed out'
    })
    def post(self, id):
        """
        Start instance
        :param id:
        :return status code
        """

        data = {
            'action': 'start',
            'timeout': 30
        }

        current_identity = import_user()
        try:
            # c = Instance.query.filter_by(name=name).first()  # USE FOR QUERY BY NAME
            c = Instance.query.filter_by(id=id).first()
            if c and (c.id in current_identity.instances or current_identity.admin):
                res = lgw.lxd_api_put('instances/' + c.name + '/state', data)

                # Delete redis cache
                redis_store.delete('instances:' + c.name + ':info')
                redis_store.delete('instances:' + c.name + ':state')

                return res.json()
            else:
                api.abort(code=403, message='Unauthorized access')
        except:
            api.abort(code=404, message='Instance doesn\'t exists')


class InstancesFreeze(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('instances_freeze')
    @api.doc(responses={
        204: 'Instance frozen',
        404: 'Instance doesn\'t exists',
        500: 'Freeze timed out'
    })
    def post(self, id):
        """
        Freeze instance
        :param id:
        :return data
        """
        data = {
            'action': 'freeze',
            'timeout': 30
        }

        current_identity = import_user()
        try:
            # c = Instance.query.filter_by(name=name).first()  # USE FOR QUERY BY NAME
            c = Instance.query.filter_by(id=id).first()
            if c and (c.id in current_identity.instances or current_identity.admin):
                res = lgw.lxd_api_put('instances/' + c.name + '/state', data)

                # Delete redis cache
                redis_store.delete('instances:' + c.name + ':info')
                redis_store.delete('instances:' + c.name + ':state')

                return res.json()
            else:
                api.abort(code=403, message='Unauthorized access')
        except:
            api.abort(code=404, message='Instance doesn\'t exists')


class InstancesUnfreeze(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('instances_unfreeze')
    @api.doc(responses={
        204: 'Instance thawed',
        404: 'Instance doesn\'t exists',
        500: 'Unfreeze timed out'
    })
    def post(self, id):
        """
        Unfreeze instance
        :param id
        :return data
        """
        data = {
            'action': 'unfreeze',
            'timeout': 30
        }

        current_identity = import_user()
        try:
            # c = Instance.query.filter_by(name=name).first()  # USE FOR QUERY BY NAME
            c = Instance.query.filter_by(id=id).first()
            if c and (c.id in current_identity.instances or current_identity.admin):
                res = lgw.lxd_api_put('instances/' + c.name + '/state', data)

                # Delete redis cache
                redis_store.delete('instances:' + c.name + ':info')
                redis_store.delete('instances:' + c.name + ':state')

                return res.json()
            else:
                api.abort(code=403, message='Unauthorized access')
        except:
            api.abort(code=404, message='Instance doesn\'t exists')


class InstancesStop(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('instances_stop')
    @api.doc(responses={
        204: 'Instance stopped',
        404: 'Instance doesn\'t exists',
        500: 'Stop timed out'
    })
    def post(self, id):
        """
        Stop instance
        :param id:
        :return data
        """
        data = {
            'action': 'stop',
            'timeout': 30
        }

        current_identity = import_user()
        try:
            # c = Instance.query.filter_by(name=name).first()  # USE FOR QUERY BY NAME
            c = Instance.query.filter_by(id=id).first()
            if c and (c.id in current_identity.instances or current_identity.admin):
                res = lgw.lxd_api_put('instances/' + c.name + '/state', data)

                # Delete redis cache
                redis_store.delete('instances:' + c.name + ':info')
                redis_store.delete('instances:' + c.name + ':state')

                return res.json()
            else:
                api.abort(code=403, message='Unauthorized access')
        except:
            api.abort(code=404, message='Instance doesn\'t exists')


class InstancesStopForce(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('instances_stop_force')
    @api.doc(responses={
        204: 'Instance stopped',
        404: 'Instance doesn\'t exists',
        500: 'Stop timed out'
    })
    def post(self, id):
        """
        Stop instance
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
            # c = Instance.query.filter_by(name=name).first()  # USE FOR QUERY BY NAME
            c = Instance.query.filter_by(id=id).first()
            if c and (c.id in current_identity.instances or current_identity.admin):
                res = lgw.lxd_api_put('instances/' + c.name + '/state', data)

                # Delete redis cache
                redis_store.delete('instances:' + c.name + ':info')
                redis_store.delete('instances:' + c.name + ':state')

                return res.json()
            else:
                api.abort(code=403, message='Unauthorized access')
        except:
            api.abort(code=404, message='Instance doesn\'t exists')


class InstancesRestart(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('instances_restart')
    @api.doc(responses={
        204: 'Instance restarted',
        404: 'Instance doesn\'t exists',
        500: 'Restart timed out'
    })
    def post(self, id):
        """
        Restart instance
        :param id:
        :return data
        """
        data = {
            'action': 'restart',
            'timeout': 30
        }

        current_identity = import_user()
        try:
            # c = Instance.query.filter_by(name=name).first()  # USE FOR QUERY BY NAME
            c = Instance.query.filter_by(id=id).first()
            if c and (c.id in current_identity.instances or current_identity.admin):
                res = lgw.lxd_api_put('instances/' + c.name + '/state', data)

                # Delete redis cache
                redis_store.delete('instances:' + c.name + ':info')
                redis_store.delete('instances:' + c.name + ':state')

                return res.json()
            else:
                api.abort(code=403, message='Unauthorized access')
        except:
            api.abort(code=404, message='Instance doesn\'t exists')


class InstancesExec(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('instances_console')
    def post(self, id):
        """
        Open instance terminal
        :param id
        :return terminal data
        """
        data = {
            'command': ['/bin/bash'],       # Command and arguments
            'environment': {},              # Optional extra environment variables to set
            'wait-for-websocket': True,     # Whether to wait for a connection before starting the process
            'record-output': False,         # Whether to store stdout and stderr (only valid with wait-for-websocket=false) (requires API extension instance_exec_recording)
            'interactive': True,            # Whether to allocate a pts device instead of PIPEs
            'width': 80,                    # Initial width of the terminal (optional)
            'height': 25,                   # Initial height of the terminal (optional)

        }

        current_identity = import_user()
        try:
            # c = Instance.query.filter_by(name=name).first()  # USE FOR QUERY BY NAME
            c = Instance.query.filter_by(id=id).first()
            if c and (c.id in current_identity.instances or current_identity.admin):
                #res = lgw.lxd_api_post('instances/' + c.name + '/console', {}) #bug with closing console
                res = lgw.lxd_api_post('instances/' + c.name + '/exec', data)
                return {'data': res.json()}
            else:
                api.abort(code=403, message='Unauthorized access')
        except:
            api.abort(code=404, message='Instance doesn\'t exists')


##################
# Snapshots API #   NEED TO WORK / ZFS LXD
##################


class SnapshotsList(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('snapshots_infos_all')
    @api.marshal_with(snapshots_fields_get_many)
    def get(self, id):
        """
        Get snapshot list
        """
        current_identity = import_user()
        instance = Instance.query.get(id)
        snapshots = []

        if instance.name and (id in current_identity.instances or current_identity.admin):
            res = lgw.lxd_api_get('instances/' + instance.name + '/snapshots?recursion=1') #recursion=1 returns objects
            for i, r in enumerate(res.json()['metadata']):
                # print(r['name'] + r['created_at'] + str(r['stateful']))
                snapshot_json = {'type': 'snapshots', 'id': i, 'attributes': {'name': r['name'], 'created_at': r['created_at'],
                                                'stateful': r['stateful']}}
                snapshots.append(snapshot_json)
            # return {'data': res.json()['metadata']}
            return {'data': snapshots}
        else:
            api.abort(code=404, message='Instance not found')

    @user_has('snapshots_create')
    @api.expect(snapshots_fields_post, validate=True)
    # @api.marshal_with(snapshots_fields_get)
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
        instance = Instance.query.get(id)

        if instance.name and (id in current_identity.instances or current_identity.admin):
            if not instance:
                api.abort(code=409, message='Snapshot name already exists')
            else:
                res = lgw.lxd_api_post(
                    'instances/' + instance.name + '/snapshots', {'name': data['name'], 'stateful': False})  # recursion=1 returns objects
                # print(res.json())
                return {'data': res.json()['metadata']}

        api.abort(code=500, message='Can\'t create instance')


class Snapshots(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('snapshots_infos')
    @api.marshal_with(snapshots_fields_get)
    def get(self, id, name):
        """
        Get snapshot
        """
        current_identity = import_user()
        instance = Instance.query.get(id)

        if instance.name and (id in current_identity.instances or current_identity.admin):
            try:
                res = lgw.lxd_api_get('instances/' + instance.name + '/snapshots/' + name)
                r = res.json()['metadata']
                # print(r)
                snapshot_json = {'type': 'snapshots', 'attributes': {'name': r['name'], 'created_at': r['created_at'],
                                                                     'stateful': r['stateful']}}
                return {'data': snapshot_json}
            except:
                api.abort(code=404, message='Snapshot doesn\'t exists')

        api.abort(code=404, message='Instance doesn\'t exists')

    @user_has('snapshots_rename')
    @api.expect(snapshots_fields_put, validate=True)
    @api.marshal_with(snapshots_fields_get)
    def put(self, id, name, d=None):
        """
        Update snapshot
        """
        if d:
            data = d
        else:
            data = request.get_json()['data']

        current_identity = import_user()
        instance = Instance.query.get(id)

        if instance.name and (id in current_identity.instances or current_identity.admin):
            try:
                res = lgw.lxd_api_get('instances/' + instance.name + '/snapshots/' + name)
                r = res.json()['metadata']
                if r['expires_at']:
                    try:
                        res = lgw.lxd_api_put('instances/' + instance.name + '/snapshots/' + name, {'expires_at': data['expires_at']})
                        return {}, 204
                    except:
                        api.abort(code=500, message='Error deleting snapshot')
            except:
                api.abort(code=404, message='Snapshot doesn\'t exists')

        api.abort(code=404, message='Instance doesn\'t exists')
        
    @user_has('snapshots_delete')
    def delete(self, id, name):
        """
        Delete snapshot
        """
        current_identity = import_user()
        instance = Instance.query.get(id)

        if instance.name and (id in current_identity.instances or current_identity.admin):
            try:
                resx = lgw.lxd_api_get('instances/' + instance.name + '/snapshots/' + name)
                if resx:
                    try:
                        res = lgw.lxd_api_delete('instances/' + instance.name + '/snapshots/' + name)
                        return {}, 204
                    except:
                        api.abort(code=500, message='Error deleting snapshot')
            except:
                api.abort(code=404, message='Snapshot doesn\'t exists')

        api.abort(code=404, message='Instance doesn\'t exists')


class SnapshotsRestore(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('snapshots_restore')
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
        instance = Instance.query.get(id)

        if instance.name and (id in current_identity.instances or current_identity.admin):
            try:
                resx = lgw.lxd_api_get('instances/' + instance.name + '/snapshots/' + name)
                if resx:
                    try:
                        res = lgw.lxd_api_put('instances/' + instance.name, {'restore': name})
                        return {}, 204
                    except:
                        api.abort(code=500, message='Error restoring snapshot')
            except:
                api.abort(code=404, message='Snapshot doesn\'t exists')

        api.abort(code=404, message='Instance doesn\'t exists')


##################
# Images API #
##################
class ImagesList(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('images_infos_all')
    # @api.marshal_with(instances_fields_get_many)
    def get(self):
        """
        Get images list
        :return: images data
        """

        res = lgw.lxd_api_get('images?recursion=1')
        return {'data': res.json()['metadata']}

    @user_has('images_create')
    def post(self):
        """
        create image
        """
        data = request.get_json()['data']
        # print(data)
        current_identity = import_user()
        if current_identity.admin:
            res = lgw.lxd_api_post('images', data=data)
            # **** wait for operation ****
            # print(res.json()['operation'])
            # op_id = (res.json()['metadata']['id'])
            # res2 = lgw.lxd_api_get('/operations/' + op_id + '/wait')
            # print(res2.json())
            # print(res.json())
            return res.json()

    @user_has('images_aliases_delete') # ???????????????????????????????????????????????????????????????????
    def delete(self, alias):
        """
        Delete alias
        """
        res = lgw.lxd_api_delete('images/' + alias)
        return res.json()['metadata']


class Images(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('images_infos')
    def get(self, fingerprint):
        """
        :return
        """
        res = lgw.lxd_api_get('images/' + fingerprint)
        return {'data': res.json()['metadata']}

    @user_has('images_update')
    def patch(self, fingerprint, d=None):
        """
        Update image
        """
        if d:
            data = d
        else:
            data = request.get_json()['data']

        res = lgw.lxd_api_patch('images/' + fingerprint, data=data)
        return res.json()['metadata']

    @user_has('images_delete')
    def delete(self, fingerprint):
        """
        Delete alias
        """
        res = lgw.lxd_api_delete('images/' + fingerprint)
        return res.json()['metadata']


class ImagesAliasesList(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('images_aliases_infos_all')
    def get(self):
        """
        :return
        """
        res = lgw.lxd_api_get('images/aliases')
        return {'data': res.json()['metadata']}

    @user_has('images_aliases_create')
    def post(self, d=None):
        """
        Create image alias
        """
        if d:
            data = d
        else:
            data = request.get_json()['data']

        res = lgw.lxd_api_post('images/aliases', data=data)
        return res.json()['metadata']


class ImagesAliases(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('images_aliases_infos')
    def get(self, alias):
        """
        :return
        """
        res = lgw.lxd_api_get('images/aliases/' + alias)
        return {'data': res.json()['metadata']}

    @user_has('images_aliases_update')
    def put(self, alias, d=None):
        """
        Update image
        """
        if d:
            data = d
        else:
            data = request.get_json()['data']

        res = lgw.lxd_api_put('images/aliases/' + alias, data=data)
        return res.json()['metadata']

    @user_has('images_aliases_update')
    def patch(self, alias, d=None):
        """
        Update image
        """
        if d:
            data = d
        else:
            data = request.get_json()['data']

        res = lgw.lxd_api_patch('images/aliases/' + alias, data=data)
        return res.json()['metadata']

    @user_has('images_aliases_update')
    def post(self, alias, d=None):
        """
        Rename image alias
        """
        if d:
            data = d
        else:
            data = request.get_json()['data']

        res = lgw.lxd_api_post('images/aliases/' + alias, data=data)
        return res.json()['metadata']

    @user_has('images_aliases_delete')
    def delete(self, alias):
        """
        Delete alias
        """
        res = lgw.lxd_api_delete('images/aliases/' + alias)
        return res.json()['metadata']


class RemoteImagesList(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('images_remote_infos_all')
    # @api.marshal_with(instances_fields_get_many)
    def get(self):
        """
        Get images list
        :return: images data
        """

        current_identity = import_user()
        if current_identity.admin:
            # res = lgw.lxd_api_get('images?recursion=1')
            res = lgw.lxd_remote_get()
            # res = requests.get('https://uk.images.linuxinstances.org' + '/1.0/images/aliases', timeout=10)
            return {'data': res.json()['metadata']}


##################
# Other API #
##################

class Operations(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('operations_infos')
    def get(self, id):
        """
        Get images list
        :return: images data
        """
        res = lgw.lxd_api_get('operations/' + id + '/wait')
        return res.json()


class LxcHostResources(Resource):
    decorators = [jwt_required, otp_confirmed]

    # @api.marshal_with(cts_hosts_fields_get)
    @user_has('resources_infos')
    def get(self):
        """
        Get lxd host resources
        :return data
        """
        json_output = lgw.lxd_api_get('resources').json()['metadata']
        return {'data': json_output}


class LxcCheckConfig(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('lxd_infos')
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
    @user_has('stats_infos')
    def get(self):
        """
        Instances stats resources
        :return data
        """

        populate_instances_table()
        current_identity = import_user()
        alist = []

        all = []
        res = lgw.lxd_api_get('instances')
        for c in res.json()['metadata']:
            all.append(c[15:])

        for ct in all:
            instance = Instance.query.filter_by(name=ct).first()
            if instance.id in current_identity.instances or current_identity.admin:
                alist.append(ct)

        json_output = lgw.cts_stats(alist, redis_store)
        return {'data': json_output}

