#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import request
from flask_restplus import Resource
from flask_jwt_extended import jwt_required
from .decorators import *
from .fields.instances import *
from .fields.snapshots import *
from .fields.lxdservers import *
from app import redis_store, app
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

        database_lxdservers_list = Server.query.all()
        for lxdserver in database_lxdservers_list:
            # starttime = time.time()
            for c in Instance.query.filter_by(location=lxdserver.name):
                #instance = Instance.query.filter_by(name=c.name).first()
                if c.id in current_identity.instances or current_identity.admin:
                    instance_json = c.__jsonapi__()


                    try:
                        instance_json.update(json.loads(redis_store.get('server:'+lxdserver.name+':instance:'+c.name+':info')))
                        instance_json['state'] = (json.loads(redis_store.get('server:'+lxdserver.name+':instance:'+c.name+':state')))
                    except TypeError:
                        res = lgw.lxd_api_get(lxdserver, 'instances/' + c.name)
                        #print(res.json())
                        instance_json.update(res.json()['metadata'])
                        res_state = lgw.lxd_api_get(lxdserver, 'instances/' + c.name + '/state')
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

        try:
            servers_id = list(id['id'] for id in data['relationships']['servers'])
            lxdserver = Server.query.filter_by(name=servers_id[0])
        except KeyError:
            pass
        except AttributeError:
            api.abort(code=500, message='Server doesn\'t exists')
        
        if 'name' in data:
            c = Instance.query.filter_by(name=data['name']).first()
            if not c:
                app.logger.info('User: %s creating new container %s', current_identity.username, data['name'])
                config = data['instance']
                # if not admin, recalculate price
                # if 'user.price' in config['config']:
                #    config['config']['user.price'] = '5'
                # print('Config2', config)
                try:
                    res = lgw.lxd_api_post(lxdserver, 'instances', data=config)
                    #print(res.text)
                    #print(res.status_code)
                except Exception as e:
                    api.abort(code=500, message='Can\'t create instance')

                if res.status_code == 202:
                    # Add instance to database
                    instance = Instance(name=data['name'], location=lxdserver.name)
                    db.session.add(instance)
                    db.session.commit()
                    # Get instance ID
                    instance = Instance.query.filter_by(
                        name=data['name']).first()

                    # Add instance to server instances
                    lxdserver.instances.append(instance.id)
                    db.session.commit()

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
                lxdserver = Server.query.filter_by(name=c.location).first()
                res = lgw.lxd_api_get(lxdserver, 'instances/' + c.name)
                instance_json = c.__jsonapi__()
                instance_json.update(res.json()['metadata'])
                res_state = lgw.lxd_api_get(lxdserver, 'instances/' + c.name + '/state')
                instance_json['state'] = res_state.json()['metadata']

                # update redis data about instance
                #redis_store.set('instances:' + c.name + ':info', json.dumps(res.json()['metadata']))
                redis_store.set('server:' + lxdserver.name + ':instance:' + c.name + ':info',
                                json.dumps(res.json()['metadata']))
                #redis_store.set('instances:' + c.name + ':state', json.dumps(res_state.json()['metadata']))
                redis_store.set('server:' + lxdserver.name + ':instance:' + c.name + ':state',
                                json.dumps(res_state.json()['metadata']))

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
            lxdserver = Server.query.filter_by(name=c.location).first()
            if c.name and (id in current_identity.instances or current_identity.admin):

                app.logger.info('User: %s updating container %s', current_identity.username, c.name)

                if 'limits_cpu' in data['config']:
                    config = {
                              'config': {'limits.cpu': str(data['config']['limits_cpu'])}}
                    try:
                        res = lgw.lxd_api_patch(lxdserver, 'instances/'+c.name, data=config)
                        # print(res.text)
                    except Exception as e:
                        api.abort(code=500, message='Can\'t create instance')
                if 'limits_memory' in data['config']:
                    config = {
                        'config': {'limits.memory': data['config']['limits_memory']}}
                    try:
                        res = lgw.lxd_api_patch(lxdserver, 'instances/'+c.name, data=config)
                        # print(res.text)
                    except Exception as e:
                        api.abort(code=500, message='Can\'t create instance')

                # Delete redis cache
                redis_store.delete('server:' + lxdserver.name + ':instance:' + c.name + ':info')
                redis_store.delete('server:' + lxdserver.name + ':instance:' + c.name + ':state')
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
            lxdserver = Server.query.filter_by(name=c.location).first()
            if c.name and (id in current_identity.instances or current_identity.admin):

                app.logger.info('User: %s updating container %s', current_identity.username, c.name)

                config = data['instance']
                try:
                    res = lgw.lxd_api_patch(lxdserver, 'instances/' + c.name, data=config)
                    #print(res.text)
                    #print(res.status_code)
                    if res.status_code == 500:
                        api.abort(code=500, message='Can\'t create instance')
                except Exception as e:
                    api.abort(code=500, message='Can\'t create instance')

                # Delete redis cache
                redis_store.delete('server:' + lxdserver.name + ':instance:' + c.name + ':info')
                redis_store.delete('server:' + lxdserver.name + ':instance:' + c.name + ':state')

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
            lxdserver = Server.query.filter_by(name=c.location).first()
            # print(c)
        except:
            api.abort(code=404, message='Instance doesn\'t exists')

        if id in current_identity.instances or current_identity.admin:

            app.logger.info('User: %s deleting container %s', current_identity.username, c.name)

            res = lgw.lxd_api_delete(lxdserver, 'instances/' + c.name)
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
            redis_store.delete('server:' + lxdserver.name + ':instance:' + c.name + ':info')
            redis_store.delete('server:' + lxdserver.name + ':instance:' + c.name + ':state')

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
            lxdserver = Server.query.filter_by(name=c.location).first()
            if c and (c.id in current_identity.instances or current_identity.admin):
                res = lgw.lxd_api_get(lxdserver, 'instances/' + c.name + '/state')
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
        #print(data)
        current_identity = import_user()
        try:
            # c = Instance.query.filter_by(name=name).first()  # USE FOR QUERY BY NAME
            c = Instance.query.filter_by(id=id).first()
            lxdserver = Server.query.filter_by(name=c.location).first()
            if c and (c.id in current_identity.instances or current_identity.admin):
                app.logger.info('User: %s updating container %s state to %s', current_identity.username, c.name, data['action'])

                res = lgw.lxd_api_put(lxdserver, 'instances/' + c.name + '/state', data)

                # Delete redis cache
                redis_store.delete('server:' + lxdserver.name + ':instance:' + c.name + ':info')
                redis_store.delete('server:' + lxdserver.name + ':instance:' + c.name + ':state')
                #print(res.json())
                return {'data': res.json()}
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
            lxdserver = Server.query.filter_by(name=c.location).first()
            if c and (c.id in current_identity.instances or current_identity.admin):

                app.logger.info('User: %s starting console on container %s', current_identity.username, c.name)

                #res = lgw.lxd_api_post('instances/' + c.name + '/console', {}) #bug with closing console
                res = lgw.lxd_api_post(lxdserver, 'instances/' + c.name + '/exec', data)

                relationships = lxdserver.get_as_relationships_exec()

                res_meta = res.json()['metadata']
                res_meta.update({'relationships': relationships})

                #print(res_meta)
                return {'data': res_meta}
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
        lxdserver = Server.query.filter_by(name=instance.location).first()

        if instance.name and (id in current_identity.instances or current_identity.admin):
            res = lgw.lxd_api_get(lxdserver, 'instances/' + instance.name + '/snapshots?recursion=1') #recursion=1 returns objects
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
        lxdserver = Server.query.filter_by(name=instance.location).first()

        if instance.name and (id in current_identity.instances or current_identity.admin):
            app.logger.info('User: %s creating snapshot on container %s', current_identity.username, instance.name)

            if not instance:
                api.abort(code=409, message='Snapshot name already exists')
            else:
                res = lgw.lxd_api_post(lxdserver,
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
        lxdserver = Server.query.filter_by(name=instance.location).first()
        if instance.name and (id in current_identity.instances or current_identity.admin):
            try:
                res = lgw.lxd_api_get(lxdserver, 'instances/' + instance.name + '/snapshots/' + name)
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
        lxdserver = Server.query.filter_by(name=instance.location).first()

        if instance.name and (id in current_identity.instances or current_identity.admin):
            try:
                app.logger.info('User: %s updating snapshot on container %s', current_identity.username, instance.name)

                res = lgw.lxd_api_get(lxdserver, 'instances/' + instance.name + '/snapshots/' + name)
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
        lxdserver = Server.query.filter_by(name=instance.location).first()

        if instance.name and (id in current_identity.instances or current_identity.admin):
            try:
                resx = lgw.lxd_api_get(lxdserver, 'instances/' + instance.name + '/snapshots/' + name)
                app.logger.info('User: %s deleting snapshot on container %s', current_identity.username, instance.name)
                if resx:
                    try:
                        res = lgw.lxd_api_delete(lxdserver, 'instances/' + instance.name + '/snapshots/' + name)
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
        lxdserver = Server.query.filter_by(name=instance.location).first()

        if instance.name and (id in current_identity.instances or current_identity.admin):
            try:
                app.logger.info('User: %s restoring snapshot on container %s', current_identity.username, instance.name)
                resx = lgw.lxd_api_get(lxdserver, 'instances/' + instance.name + '/snapshots/' + name)
                if resx:
                    try:
                        res = lgw.lxd_api_put(lxdserver, 'instances/' + instance.name, {'restore': name})
                        return {}, 204
                    except:
                        api.abort(code=500, message='Error restoring snapshot')
            except:
                api.abort(code=404, message='Snapshot doesn\'t exists')

        api.abort(code=404, message='Instance doesn\'t exists')


##################
# Images API #
##################
class ImagesListAll(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('images_infos_all')
    def get(self):
        """
        Get images list
        :return: images data
        """

        response = []
        database_lxdservers_list = Server.query.all()
        for lxdserver in database_lxdservers_list:
            relationships = lxdserver.get_as_relationships()

            res = lgw.lxd_api_get(lxdserver, 'images?recursion=1')
            res_meta = res.json()['metadata']
            for r in res_meta:
                r.update({'relationships': relationships})
            response += res_meta
        # print(response)
        return {'data': response}


class ImagesList(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('images_infos_all')
    def get(self, server):
        """
        Get images list from server x
        :return: images data
        """

        response = []

        lxdserver = Server.query.filter_by(name=server).first()
        relationships = lxdserver.get_as_relationships()

        res = lgw.lxd_api_get(lxdserver, 'images?recursion=1')
        res_meta = res.json()['metadata']
        for r in res_meta:
            r.update({'relationships': relationships})
        response += res_meta
        # print(response)
        return {'data': response}

    @user_has('images_create')
    def post(self, server):
        """
        create image on server x
        """
        data = request.get_json()['data']
        current_identity = import_user()
        lxdserver = Server.query.filter_by(name=server).first()
        if current_identity.admin:
            app.logger.info('User: %s creating new image', current_identity.username)
            res = lgw.lxd_api_post(lxdserver, 'images', data=data)
            return res.json()


class Images(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('images_infos')
    def get(self, server, fingerprint):
        """
        :return
        """
        lxdserver = Server.query.filter_by(name=server).first()
        res = lgw.lxd_api_get(lxdserver, 'images/' + fingerprint)
        return {'data': res.json()['metadata']}

    @user_has('images_update')
    def patch(self, server, fingerprint, d=None):
        """
        Update image
        """
        if d:
            data = d
        else:
            data = request.get_json()['data']

        lxdserver = Server.query.filter_by(name=server).first()
        app.logger.info('User: %s updating image %s', import_user().username, fingerprint)
        res = lgw.lxd_api_patch(lxdserver, 'images/' + fingerprint, data=data)
        return res.json()['metadata']

    @user_has('images_delete')
    def delete(self, server, fingerprint):
        """
        Delete alias
        """
        lxdserver = Server.query.filter_by(name=server).first()
        app.logger.info('User: %s deleting image %s', import_user().username, fingerprint)
        res = lgw.lxd_api_delete(lxdserver, 'images/' + fingerprint)
        return res.json()['metadata']


class ImagesAliasesList(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('images_aliases_infos_all')
    def get(self):
        """
        :return
        """
        response = []
        database_lxdservers_list = Server.query.all()
        for lxdserver in database_lxdservers_list:
            relationships = lxdserver.get_as_relationships()

            res = lgw.lxd_api_get(lxdserver, 'images/aliases')
            res_meta = res.json()['metadata']
            for r in res_meta:
                r.update({'relationships': relationships})
            response += res_meta
        return {'data': response}


    @user_has('images_aliases_create')
    def post(self, d=None):
        """
        Create image alias
        """
        if d:
            data = d
        else:
            data = request.get_json()['data']

        app.logger.info('User: %s creating new image alias', import_user().username)
        res = lgw.lxd_api_post('images/aliases', data=data)
        return res.json()['metadata']


class ImagesAliases(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('images_aliases_infos')
    def get(self, server, alias):
        """
        :return
        """
        lxdserver = Server.query.filter_by(name=server).first()
        res = lgw.lxd_api_get(lxdserver, 'images/aliases/' + alias)
        return {'data': res.json()['metadata']}

    @user_has('images_aliases_update')
    def put(self, server, alias, d=None):
        """
        Update image
        """
        if d:
            data = d
        else:
            data = request.get_json()['data']

        lxdserver = Server.query.filter_by(name=server).first()
        app.logger.info('User: %s updating image alias %s', import_user().username, alias)
        res = lgw.lxd_api_put(lxdserver, 'images/aliases/' + alias, data=data)
        return res.json()['metadata']

    @user_has('images_aliases_update')
    def patch(self, server, alias, d=None):
        """
        Update image
        """
        if d:
            data = d
        else:
            data = request.get_json()['data']

        lxdserver = Server.query.filter_by(name=server).first()
        app.logger.info('User: %s updating image alias %s', import_user().username, alias)
        res = lgw.lxd_api_patch(lxdserver, 'images/aliases/' + alias, data=data)
        return res.json()['metadata']

    @user_has('images_aliases_update')
    def post(self, server, alias, d=None):
        """
        Rename image alias
        """
        if d:
            data = d
        else:
            data = request.get_json()['data']

        lxdserver = Server.query.filter_by(name=server).first()
        app.logger.info('User: %s rename image alias %s', import_user().username, alias)
        res = lgw.lxd_api_post(lxdserver, 'images/aliases/' + alias, data=data)
        return res.json()['metadata']

    @user_has('images_aliases_delete')
    def delete(self, server, alias):
        """
        Delete alias
        """
        lxdserver = Server.query.filter_by(name=server).first()
        app.logger.info('User: %s deleting image alias %s', import_user().username, alias)
        res = lgw.lxd_api_delete(lxdserver, 'images/aliases/' + alias)
        return res.json()['metadata']


class RemoteImagesList(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('images_remote_infos_all')
    def get(self):
        """
        Get images list
        :return: images data
        """

        current_identity = import_user()
        if current_identity.admin:
            res = lgw.lxd_remote_get()
            # res = requests.get('https://uk.images.linuxinstances.org' + '/1.0/images/aliases', timeout=10)
            return {'data': res.json()['metadata']}


##################
# Universal API #
##################
class UniversalsListAll(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('universals_infos_all')
    def get(self, url):
        """
        Get 'universal' list
        :return: 'universal' data
        """
        #if url in ['instances', 'containers', 'virtual-machines', 'cluster', 'resources', 'events', 'operations']:
        #    api.abort(code=404, message='URL: '+url+' doesn\'t exists')

        response = []
        database_lxdservers_list = Server.query.all()
        for lxdserver in database_lxdservers_list:
            relationships = lxdserver.get_as_relationships()
            res = lgw.lxd_api_get(lxdserver, url + '?recursion=1')
            res_meta = res.json()['metadata']
            # if response is list of objects
            if isinstance(res_meta, list):
                for r in res_meta:
                    if not isinstance(r, str):
                        r.update({'relationships': relationships})
                response += res_meta
            else:
                res_meta.update({'relationships': relationships})
                response.append(res_meta)
        return {'data': response}


class UniversalsList(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('universals_infos_all')
    def get(self, url, server):
        """
        Get 'universal' list
        :return: 'universal' data
        """
        #if url in ['instances', 'containers', 'virtual-machines', 'cluster', 'resources', 'events', 'operations']:
        #    api.abort(code=404, message='URL: '+url+' doesn\'t exists')

        response = []
        lxdserver = Server.query.filter_by(name=server).first()

        relationships = lxdserver.get_as_relationships()
        res = lgw.lxd_api_get(lxdserver, url + '?recursion=1')
        res_meta = res.json()['metadata']
        # if response is list of objects
        if isinstance(res_meta, list):
            for r in res_meta:
                if not isinstance(r, str):
                    r.update({'relationships': relationships})
            response += res_meta
        else:
            res_meta.update({'relationships': relationships})
            response.append(res_meta)
        return {'data': response}

    @user_has('universals_create')
    def post(self, url, server):
        """
        Create 'universal'
        """
        data = request.get_json()['data']
        lxdserver = Server.query.filter_by(name=server).first()
        # print(data)
        current_identity = import_user()
        if current_identity.admin and lxdserver:
            app.logger.info('User: %s creating something on %s', import_user().username, url)
            res = lgw.lxd_api_post(lxdserver, url, data=data)
            return res.json()


class Universals(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('universals_infos')
    def get(self, url, server, name):
        """
        :return
        """
        lxdserver = Server.query.filter_by(name=server).first()
        res = lgw.lxd_api_get(lxdserver, url + '/' + name)
        return {'data': res.json()['metadata']}

    @user_has('universals_update')
    def put(self, url, server, name, d=None):
        """
        Update 'universal'
        """
        if d:
            data = d
        else:
            data = request.get_json()['data']

        lxdserver = Server.query.filter_by(name=server).first()
        app.logger.info('User: %s updating something on %s', import_user().username, url)
        res = lgw.lxd_api_put(lxdserver, url + '/' + name, data=data)
        return res.json()['metadata']

    @user_has('universals_update')
    def patch(self, url, server, name, d=None):
        """
        Update 'universal'
        """
        if d:
            data = d
        else:
            data = request.get_json()['data']

        lxdserver = Server.query.filter_by(name=server).first()
        app.logger.info('User: %s updating something on %s', import_user().username, url)
        res = lgw.lxd_api_patch(lxdserver, url + '/' + name, data=data)
        return res.json()['metadata']

    @user_has('universals_rename')
    def post(self, url, server, name, d=None):
        """
        Rename 'universal'
        """
        if d:
            data = d
        else:
            data = request.get_json()['data']

        lxdserver = Server.query.filter_by(name=server).first()
        app.logger.info('User: %s renaming something on %s', import_user().username, url)
        res = lgw.lxd_api_post(lxdserver, url + '/' + name, data=data)
        return res.json()['metadata']

    @user_has('universals_delete')
    def delete(self, url, server, name):
        """
        Delete 'universal'
        """
        lxdserver = Server.query.filter_by(name=server).first()
        app.logger.info('User: %s deleting something on %s', import_user().username, url)
        res = lgw.lxd_api_delete(lxdserver, url + '/' + name)
        return res.json()['metadata']


##################
# Other API #
##################

class Operations(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('operations_infos')
    def get(self, server, id):
        """
        Get images list
        :return: images data
        """
        lxdserver = Server.query.filter_by(name=server).first()
        res = lgw.lxd_api_get(lxdserver, 'operations/' + id + '/wait')
        return res.json()


class LxdConfig(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('lxd_server_infos')
    def get(self, server):
        """
        Check LXC configuration (lxc-checkconfig)
        :return data
        """
        lxdserver = Server.query.filter_by(name=server).first()
        conf = lgw.lxd_api_get_config(lxdserver).json()['metadata']
        return {'data': conf}


class LxdServersList(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('servers_infos_all')
    @api.marshal_with(lxdservers_fields_get_many)
    def get(self):
        """
        Get list of used lxd servers
        :return: data
        """
        servers = Server.query.all()
        servers_list = []

        for server in servers:
            servers_list.append(server.__jsonapi__())
            # update redis DB with actual servers list
            redis_store.set('servers:' + server.name, json.dumps(server.__jsonapi__('redis')))

        #print(servers_list)
        return {'data': servers_list}

    @user_has('servers_create')
    @api.marshal_with(lxdservers_fields_get)
    @api.expect(lxdservers_fields_post, validate=False)
    def post(self):
        """
        Add new lxd server to lxdmanager
        """

        data = request.get_json()['data']
        #print(data)

        current_identity = import_user()
        if current_identity.admin:
            app.logger.info('User: %s adding new server to lxdmanager', import_user().username)
            res = lgw.send_cert_to_server(data['name'], data['address'], data['password'])

            server = Server()

            server.name = data['name']
            server.address = data['address']
            server.exec_address = data['exec_address']
            server.verify = data['verify']
            server.key_private = data['name'] + '_key.key'
            server.key_public = data['name'] + '_key.crt'

            db.session.add(server)
            db.session.commit()

            # update redis DB with actual server
            redis_store.set('servers:' + server.name, json.dumps(server.__jsonapi__('redis')))

        return res.json()


class LxdServers(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('servers_infos')
    @api.marshal_with(lxdservers_fields_get)
    def get(self, name):
        """
        Get lxd server by name
        :return: data
        """
        server = Server.query.filter_by(name=name).first()
        return {'data': server.__jsonapi__()}

    @user_has('servers_delete')
    def delete(self, name):
        """
        Delete lxd server by name
        :return: data
        """
        server = Server.query.filter_by(name=name).first()
        # delete server from redis DB
        app.logger.info('User: %s deleting server on %s', import_user().username, name)
        current_identity = import_user()
        if current_identity.admin:
            redis_store.delete('servers:' + server.name)
            database_instances_list = Instance.query.filter_by(location=server.name)
            for inst in database_instances_list:
                db.session.delete(inst)
                db.session.commit()

            db.session.delete(server)
            db.session.commit()

            return {}, 204
        return {}, 500




