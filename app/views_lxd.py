#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import request
from flask_restplus import Resource
from flask_jwt_extended import jwt_required
from .decorators import *
from .fields.containers import *
from .fields.stats import *
from .fields.snapshots import *
from .fields.hosts import *
import lgw


##################
# Containers API #
##################
class ContainersList(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('containers_infos_all')
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
                # url = '/api/v1/containers/' + str(i.id)
                # container_json['attributes']['url'] = url

                res = lgw.lxd_api_get('containers/' + c.name)
                container_json.update(res.json()['metadata'])
                res_state = lgw.lxd_api_get('containers/' + c.name + '/state')
                container_json['state'] = res_state.json()['metadata']
                containers.append(container_json)

        return {'data': containers}

    @user_has('containers_create')
    @api.expect(containers_fields_post, validate=False)
    # @api.marshal_with(containers_fields_get)
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
        # print(data)
        
        if 'name' in data:
            c = Container.query.filter_by(name=data['name']).first()
            if not c:
                config = {'name': data['name'],
                          # 'source': {'type': 'image',
                          #           'mode': 'pull',
                          #           'server': 'https://uk.images.linuxcontainers.org',
                          #           'protocol': 'simplestreams',
                          #           'alias': data['attributes']['source']['alias']},
                          'source': data['source'],
                          'profile': 'zfs',
                          'config': {},
                          # 'devices': {'root': {'path': '/', 'pool': 'zfs', 'type': 'disk', 'size': '3GB'}}
                          }
                          # 'devices': {'root': {'path': '/', 'pool': 'lxd','type': 'disk', 'size': '10GB'}}}
                if 'limits_cpu' in data['config']:
                    config['config']['limits.cpu'] = str(data['config']['limits_cpu'])
                if 'limits_memory' in data['config']:
                    config['config']['limits.memory'] = data['config']['limits_memory']
                if 'price' in data['config']:
                    config['config']['user.price'] = data['config']['price']
                if 'pool_name' in data['config']:
                    if data['config']['pool_name'] != '':
                        config['devices'] = {'root': {'path': '/', 'pool': data['config']['pool_name'], 'type': 'disk'}}
                        if 'limits_disk' in data['config']:
                            config['devices']['root']['size'] = data['config']['limits_disk']

                try:
                    res = lgw.lxd_api_post('containers', data=config)
                    # print(res.text)
                except Exception as e:
                    api.abort(code=500, message='Can\'t create container')

                if res.status_code == 202:
                    # Add container to database
                    container = Container(name=data['name'])
                    db.session.add(container)
                    db.session.commit()
                    # Get container ID
                    container = Container.query.filter_by(
                        name=data['name']).first()
                    # Add container to allowed users
                    if current_identity.admin:
                        try:
                            users_id = list(id['id'] for id in data['relationships']['users'])
                            for user_id in users_id:
                                user = User.query.get(user_id)
                                user.containers.append(container.id)
                                db.session.commit()
                        except KeyError:
                            pass
                        except AttributeError:
                            api.abort(code=500, message='User doesn\'t exists')
                    # Add container to current user
                    else:
                        user = User.query.get(current_identity.id)
                        user.containers.append(container.id)
                        db.session.commit()
                else:
                    api.abort(code=res.status_code, message='Error when creating container')

                # container_json = container.__jsonapi__()
                # return {'data': container_json}
                return res.json()
            api.abort(code=409, message='Container already exists')


class Containers(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('containers_infos')
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
                container_json.update(res.json()['metadata'])
                res_state = lgw.lxd_api_get('containers/' + c.name + '/state')
                container_json['state'] = res_state.json()['metadata']

                return {'data': container_json}
            else:
                api.abort(code=403, message='Unauthorized access')
        except KeyError:
            api.abort(code=404, message='Container doesn\'t exists')


    @user_has('containers_update')
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
            if c.name and (id in current_identity.containers or current_identity.admin):
                if 'limits_cpu' in data['config']:
                    config = {
                              'config': {'limits.cpu': str(data['config']['limits_cpu'])}}
                    try:
                        res = lgw.lxd_api_patch('containers/'+c.name, data=config)
                        # print(res.text)
                    except Exception as e:
                        api.abort(code=500, message='Can\'t create container')
                if 'limits_memory' in data['config']:
                    config = {
                        'config': {'limits.memory': data['config']['limits_memory']}}
                    try:
                        res = lgw.lxd_api_patch('containers/'+c.name, data=config)
                        # print(res.text)
                    except Exception as e:
                        api.abort(code=500, message='Can\'t create container')

            else:
                api.abort(code=404, message='Container doesn\'t exists')
        except:
            api.abort(code=404, message='Container doesn\'t exists')

        return {'data': data}

    @user_has('containers_delete')
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
            # print(c)
        except:
            api.abort(code=404, message='Container doesn\'t exists')

        if id in current_identity.containers or current_identity.admin:
            res = lgw.lxd_api_delete('containers/' + c.name)
            # print(res.status_code)
            if res.status_code == 400:
                api.abort(code=404, message='Container is running')
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

    @user_has('containers_state_infos')
    # @api.marshal_with(containers_fields_get)
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
                return {'data': res.json()}
            else:
                api.abort(code=403, message='Unauthorized access')
        except:
            api.abort(code=404, message='Container doesn\'t exists')

    @user_has('containers_state_update')
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
            # c = Container.query.filter_by(name=name).first()  # USE FOR QUERY BY NAME
            c = Container.query.filter_by(id=id).first()
            if c and (c.id in current_identity.containers or current_identity.admin):
                res = lgw.lxd_api_put('containers/' + c.name + '/state', data)
                return {'data': res.json()}
            else:
                api.abort(code=403, message='Unauthorized access')
        except:
            api.abort(code=404, message='Container doesn\'t exists')


class ContainersStart(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('containers_start')
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

    @user_has('containers_freeze')
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

    @user_has('containers_unfreeze')
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

    @user_has('containers_stop')
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

    @user_has('containers_stop_force')
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

    @user_has('containers_restart')
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

    @user_has('containers_console')
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
        # data = {}

        current_identity = import_user()
        try:
            # c = Container.query.filter_by(name=name).first()  # USE FOR QUERY BY NAME
            c = Container.query.filter_by(id=id).first()
            if c and (c.id in current_identity.containers or current_identity.admin):
                res = lgw.lxd_api_post('containers/' + c.name + '/console', {}) #'/exec', data
                # return res.json()
                # return {'data': {'type': 'terminal', 'id': id, 'attributes': res.json()}}, 201
                return {'data': res.json()}
            else:
                api.abort(code=403, message='Unauthorized access')
        except:
            api.abort(code=404, message='Container doesn\'t exists')


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
        container = Container.query.get(id)
        snapshots = []

        if container.name and (id in current_identity.containers or current_identity.admin):
            res = lgw.lxd_api_get('containers/' + container.name + '/snapshots?recursion=1') #recursion=1 returns objects
            for i, r in enumerate(res.json()['metadata']):
                # print(r['name'] + r['created_at'] + str(r['stateful']))
                snapshot_json = {'type': 'snapshots', 'id': i, 'attributes': {'name': r['name'], 'created_at': r['created_at'],
                                                'stateful': r['stateful']}}
                snapshots.append(snapshot_json)
            # return {'data': res.json()['metadata']}
            return {'data': snapshots}
        else:
            api.abort(code=404, message='Container not found')

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
        container = Container.query.get(id)

        if container.name and (id in current_identity.containers or current_identity.admin):
            if not container:
                api.abort(code=409, message='Snapshot name already exists')
            else:
                res = lgw.lxd_api_post(
                    'containers/' + container.name + '/snapshots', {'name': data['name'], 'stateful': False})  # recursion=1 returns objects
                # print(res.json())
                return {'data': res.json()['metadata']}

        api.abort(code=500, message='Can\'t create container')


class Snapshots(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('snapshots_infos')
    @api.marshal_with(snapshots_fields_get)
    def get(self, id, name):
        """
        Get snapshot
        """
        current_identity = import_user()
        container = Container.query.get(id)

        if container.name and (id in current_identity.containers or current_identity.admin):
            try:
                res = lgw.lxd_api_get('containers/' + container.name + '/snapshots/' + name)
                r = res.json()['metadata']
                # print(r)
                snapshot_json = {'type': 'snapshots', 'attributes': {'name': r['name'], 'created_at': r['created_at'],
                                                                     'stateful': r['stateful']}}
                return {'data': snapshot_json}
            except:
                api.abort(code=404, message='Snapshot doesn\'t exists')

        api.abort(code=404, message='Container doesn\'t exists')

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
        container = Container.query.get(id)

        if container.name and (id in current_identity.containers or current_identity.admin):
            try:
                res = lgw.lxd_api_get('containers/' + container.name + '/snapshots/' + name)
                r = res.json()['metadata']
                if r['expires_at']:
                    try:
                        res = lgw.lxd_api_put('containers/' + container.name + '/snapshots/' + name, {'expires_at': data['expires_at']})
                        return {}, 204
                    except:
                        api.abort(code=500, message='Error deleting snapshot')
            except:
                api.abort(code=404, message='Snapshot doesn\'t exists')

        api.abort(code=404, message='Container doesn\'t exists')
        
    @user_has('snapshots_delete')
    def delete(self, id, name):
        """
        Delete snapshot
        """
        current_identity = import_user()
        container = Container.query.get(id)

        if container.name and (id in current_identity.containers or current_identity.admin):
            try:
                resx = lgw.lxd_api_get('containers/' + container.name + '/snapshots/' + name)
                if resx:
                    try:
                        res = lgw.lxd_api_delete('containers/' + container.name + '/snapshots/' + name)
                        return {}, 204
                    except:
                        api.abort(code=500, message='Error deleting snapshot')
            except:
                api.abort(code=404, message='Snapshot doesn\'t exists')

        api.abort(code=404, message='Container doesn\'t exists')


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
        container = Container.query.get(id)

        if container.name and (id in current_identity.containers or current_identity.admin):
            try:
                resx = lgw.lxd_api_get('containers/' + container.name + '/snapshots/' + name)
                if resx:
                    try:
                        res = lgw.lxd_api_put('containers/' + container.name, {'restore': name})
                        return {}, 204
                    except:
                        api.abort(code=500, message='Error restoring snapshot')
            except:
                api.abort(code=404, message='Snapshot doesn\'t exists')

        api.abort(code=404, message='Container doesn\'t exists')


##################
# Images API #
##################
class ImagesList(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('images_infos_all')
    # @api.marshal_with(containers_fields_get_many)
    def get(self):
        """
        Get images list
        :return: images data
        """

        # current_identity = import_user()
        # if current_identity.admin:
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
            print(res.json()['operation'])
            op_id = (res.json()['metadata']['id'])
            # res2 = lgw.lxd_api_get('/operations/' + op_id + '/wait')
            # print(res2.json())
            print(res.json())
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

        # print(data)
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

    @user_has('images_aliases_rename')
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
    # @api.marshal_with(containers_fields_get_many)
    def get(self):
        """
        Get images list
        :return: images data
        """

        current_identity = import_user()
        if current_identity.admin:
            # res = lgw.lxd_api_get('images?recursion=1')
            res = lgw.lxd_remote_get()
            # res = requests.get('https://uk.images.linuxcontainers.org' + '/1.0/images/aliases', timeout=10)
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
        # return {'data': {'attributes': json_output}}
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
        # return {'data': {'attributes': conf, 'type': 'checkconfig', 'id': 0 }}
        return {'data': conf}

        
class CtsStats(Resource):
    decorators = [jwt_required, otp_confirmed]

    @api.marshal_with(cts_stats_fields_get)
    @user_has('stats_infos')
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
        return {'data': json_output}

