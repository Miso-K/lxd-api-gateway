#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import request
from flask_restplus import Resource
from flask_jwt_extended import fresh_jwt_required, jwt_required, create_access_token, \
    jwt_refresh_token_required, create_refresh_token, get_jti, get_raw_jwt, get_jwt_identity
from app import db, api, redis_store, app
from .decorators import *
from .fields.auth import *
from .fields.users import *
from .fields.groups import *
from .fields.abilities import *
from .fields.requests import *
from .fields.lxdconfig import *
from .fields.lxdcerts import *
import lgw
import time
import configparser


class Auth(Resource):

    @api.marshal_with(auth_fields_get)
    @api.expect(auth_fields_post, validate=True)
    def post(self):
        """
        Get Json Web Token without confirmation
        :return access_token
        :return refresh_token
        """
        request_data = request.get_json()
        username = request_data['username']
        password = request_data['password']

        user = User.query.filter_by(username=username).first()

        if not user or not user.verify_password(password):
            api.abort(code=401, message='Incorrect user or password')

        user.otp_confirmed = True

        # use if user has otp enabled
        if user.get_otp_type():
            if user.get_otp_type() == 'email':
                eotp_secret = user.create_eotp()
                # print(eotp_secret)
                lgw.send_otp_email(eotp_secret, user.email)  # send email with otp
            user.otp_confirmed = False
            access_token = create_access_token(identity=user, fresh=False)
            ret = {'access_token': access_token}
            access_jti = get_jti(encoded_token=access_token)
            redis_store.set('access_jti:' + access_jti, 'false', app.config['OTP_ACCESS_TOKEN_EXPIRES'])
            # print(redis_store.get(access_jti) + ' ' + access_jti)
            return ret

        access_token = create_access_token(identity=user, fresh=True)
        refresh_token = create_refresh_token(identity=user)
        access_jti = get_jti(encoded_token=access_token)
        refresh_jti = get_jti(encoded_token=refresh_token)
        redis_store.set('access_jti:' + access_jti, 'false', app.config['ACCESS_TOKEN_EXPIRES'])
        redis_store.set('refresh_jti:' + refresh_jti, 'false', app.config['REFRESH_TOKEN_EXPIRES'])
        ret = {'access_token': access_token,
               'refresh_token': refresh_token}
        return ret


class AuthOtp(Resource):
    decorators = [jwt_required]

    @api.marshal_with(auth_otp_fields_get)
    @api.expect(auth_otp_fields_post, validate=True)
    def post(self):
        """
        Get Json Web Token with confirmation (after correct OTP key)
        :return new access_token
        :return new refresh_token
        """
        request_data = request.get_json()
        secret = request_data['secret']
        # print(secret)
        user = import_user()

        # revoke otp_access_token
        jti = get_raw_jwt()['jti']
        redis_store.set('access_jti:' + jti, 'true', app.config['OTP_ACCESS_TOKEN_EXPIRES'])

        if user.get_otp_type() == 'totp':
            if not user.verify_totp(secret):
                api.abort(code=401, message='Incorrect secret code')
        elif user.get_otp_type() == 'email':
            if not user.verify_eotp(secret):
                api.abort(code=401, message='Incorrect secret code')
        else:
            api.abort(code=401, message='Incorrect otp type')

        user.otp_confirmed = True

        access_token = create_access_token(identity=user, fresh=True)
        refresh_token = create_refresh_token(identity=user)
        access_jti = get_jti(encoded_token=access_token)
        refresh_jti = get_jti(encoded_token=refresh_token)
        redis_store.set('access_jti:' + access_jti, 'false', app.config['ACCESS_TOKEN_EXPIRES'])
        redis_store.set('refresh_jti:' + refresh_jti, 'false', app.config['REFRESH_TOKEN_EXPIRES'])
        ret = {'access_token': access_token,
               'refresh_token': refresh_token}
        return ret


class AuthRefresh(Resource):
    decorators = [jwt_refresh_token_required]

    #@api.marshal_with(auth_fields_get)
    def post(self):
        """
        Get new token with valid token
        :return new access_token
        """
        user = import_user()
        user.otp_confirmed = True
        access_token = create_access_token(identity=user, fresh=False)
        access_jti = get_jti(encoded_token=access_token)
        redis_store.set('access_jti:' + access_jti, 'false', app.config['ACCESS_TOKEN_EXPIRES'])
        ret = {
            'access_token': access_token
        }
        return ret


class AuthCheck(Resource):
    decorators = [jwt_required, otp_confirmed]

    @api.doc(responses={
        200: 'Token OK',
        401: 'Token invalid or expired',
        422: 'Signature verification failed'
    })
    def get(self):
        """
        Check token
        """
        return {}, 200


# Endpoint for revoking the current users access token
class AuthLogout(Resource):
    decorators = [jwt_required]

    def delete(self):
        """
        Revoke token
        """
        jti = get_raw_jwt()['jti']
        if not jti:
            api.abort(code=404, message='Token not found')
        redis_store.set('access_jti:' + jti, 'true', app.config['ACCESS_TOKEN_EXPIRES'])
        return {"msg": "Access token revoked"}, 200


class UsersList(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('users_infos_all')
    @api.marshal_with(users_fields_get_many)
    def get(self):
        """
        Get users list
        """
        populate_containers_table()
        users = User.query.all()
        users_list = []

        for user in users:
            users_list.append(user.__jsonapi__())

        return {'data': users_list}

    @user_has('users_create')
    @api.expect(users_fields_post, validate=True)
    @api.marshal_with(users_fields_get)
    def post(self):
        """
        Create user
        """
        current_identity = import_user()
        data = request.get_json()['data']
        if User.query.filter_by(username=data['attributes']['username']).first():
            api.abort(code=409, message='User already exists')

        user = User()

        user.username = data['attributes']['username']
        user.name = data['attributes']['name']
        user.hash_password(data['attributes']['password'])

        if 'admin' in data['attributes'] and current_identity.admin:
            user.admin = data['attributes']['admin']
        if 'email' in data['attributes']:
            user.email = data['attributes']['email']
        if 'phone' in data['attributes']:
            user.phone = data['attributes']['phone']
        if 'address' in data['attributes']:
            user.address = data['attributes']['address']
        if 'city' in data['attributes']:
            user.city = data['attributes']['city']
        if 'country' in data['attributes']:
            user.country = data['attributes']['country']
        if 'postal_code' in data['attributes']:
            user.postal_code = data['attributes']['postal_code']
        if 'ico' in data['attributes']:
            user.ico = data['attributes']['ico']
        if 'ic_dph' in data['attributes']:
            user.ic_dph = data['attributes']['ic_dph']
        if 'dic' in data['attributes']:
            user.dic = data['attributes']['dic']
        if 'language' in data['attributes']:
            user.language = data['attributes']['language']
        if 'otp_type' in data['attributes']:
            if data['attributes']['otp_type'] == 'none':
                user.otp_type = None
            else:
                user.otp_type = data['attributes']['otp_type']

        try:
            user.groups = list(id['id'] for id in data[
                               'relationships']['groups']['data'])
        except KeyError:
            pass

        try:
            user.containers = list(id['id'] for id in data[
                                   'relationships']['containers']['data'])
        except KeyError:
            pass

        db.session.add(user)
        db.session.commit()

        return {'data': user.__jsonapi__()}, 201


class Users(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('users_infos')
    @api.marshal_with(users_fields_get)
    def get(self, id):
        """
        Get user
        """
        populate_containers_table()
        user = User.query.get(id)

        if not user:
            api.abort(code=404, message='User not found')

        return {'data': user.__jsonapi__()}

    @user_has('users_update')
    @api.expect(users_fields_put, validate=True)
    @api.marshal_with(users_fields_get)
    def put(self, id):
        """
        Update user
        """
        current_identity = import_user()
        user = User.query.get(id)

        if not user:
            api.abort(code=404, message='User not found')

        data = request.get_json()['data']

        if 'admin' in data['attributes'] and current_identity.admin:
            user.admin = data['attributes']['admin']
        if 'name' in data['attributes']:
            user.name = data['attributes']['name']
        if 'email' in data['attributes']:
            user.email = data['attributes']['email']
        if 'phone' in data['attributes']:
            user.phone = data['attributes']['phone']
        if 'address' in data['attributes']:
            user.address = data['attributes']['address']
        if 'city' in data['attributes']:
            user.city = data['attributes']['city']
        if 'country' in data['attributes']:
            user.country = data['attributes']['country']
        if 'postal_code' in data['attributes']:
            user.postal_code = data['attributes']['postal_code']
        if 'ico' in data['attributes']:
            user.ico = data['attributes']['ico']
        if 'ic_dph' in data['attributes']:
            user.ic_dph = data['attributes']['ic_dph']
        if 'dic' in data['attributes']:
            user.dic = data['attributes']['dic']
        if 'language' in data['attributes']:
            user.language = data['attributes']['language']

        if 'password' in data['attributes'] and current_identity.admin:
            user.hash_password(data['attributes']['password'])

        try:
            user.groups = list(id['id'] for id in data[
                               'relationships']['groups']['data'])
        except KeyError:
            pass

        try:
            user.containers = list(id['id'] for id in data[
                                   'relationships']['containers']['data'])
        except KeyError:
            pass

        if len(data) > 0:
            db.session.commit()

        return {'data': user.__jsonapi__()}

    @user_has('users_delete')
    def delete(self, id):
        """
        Delete user
        """
        user = User.query.get(id)

        if not user:
            api.abort(code=404, message='User not found')

        db.session.delete(user)
        db.session.commit()

        return {}, 204


class Me(Resource):
    decorators = [jwt_required, otp_confirmed]

    @api.marshal_with(users_fields_get)
    def get(self):
        """
        Get me
        """
        populate_containers_table()
        current_identity = import_user()
        return {'data': current_identity.__jsonapi__()}

    @user_has('me_edit')
    #@api.expect(users_fields_put, validate=True)
    @api.marshal_with(users_fields_get)
    def put(self):
        """
        Update me
        """
        current_identity = import_user()
        user = User.query.get(current_identity.id)

        data = request.get_json()['data']

        if 'name' in data['attributes']:
            user.name = data['attributes']['name']
        if 'email' in data['attributes']:
            user.email = data['attributes']['email']
        if 'phone' in data['attributes']:
            user.phone = data['attributes']['phone']
        if 'address' in data['attributes']:
            user.address = data['attributes']['address']
        if 'city' in data['attributes']:
            user.city = data['attributes']['city']
        if 'country' in data['attributes']:
            user.country = data['attributes']['country']
        if 'postal_code' in data['attributes']:
            user.postal_code = data['attributes']['postal_code']
        if 'ico' in data['attributes']:
            user.ico = data['attributes']['ico']
        if 'ic_dph' in data['attributes']:
            user.ic_dph = data['attributes']['ic_dph']
        if 'dic' in data['attributes']:
            user.dic = data['attributes']['dic']
        if 'langugage' in data['attributes']:
            user.language = data['attributes']['language']
        if 'otp_type' in data['attributes']:
            if data['attributes']['otp_type'] == 'none':
                user.otp_type = None
            else:
                user.otp_type = data['attributes']['otp_type']

        if 'cur_password' in data['attributes']:
            cur_password = data['attributes']['cur_password']
            #print('before verify')
            #print(data['attributes'])
            if 'new_password' in data['attributes'] and user.verify_password(cur_password):
                if data['attributes']['new_password'] == data['attributes']['confirm_password']:
                    user.hash_password(data['attributes']['new_password'])
            else:
                api.abort(code=401, message='Incorrect user or password')

        # Not secure for user to change his group or container

        if len(data) > 0:
            db.session.commit()

        return {'data': user.__jsonapi__()}

    # Stupid - user delete himself?
    #@user_has('me_edit')
    #def delete(self):
    #    """
    #    Delete me (stupid)
    #    """
    #    current_identity = import_user()
    #    user = User.query.get(current_identity.id)
    #
    #    db.session.delete(user)
    #    db.session.commit()
    #
    #    return {}, 204

class MeOtp(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('me_otp')
    def post(self):
        """
        Generate totp secret
        User can set totp secret only once
        """
        current_identity = import_user()
        user = User.query.get(current_identity.id)

        if not user:
            api.abort(code=404, message='User not found')

        # if user has otp_secret do not create new
        if not user.otp_type:
            try:
                user.otp_type = 'totp'
                user.add_totp_secret()
            except Exception as e:
                print(e)
                api.abort(code=500, message='Can\'t generate otp secret')
        else:
            api.abort(code=500, message='User has otp secret set')

        db.session.commit()
        json_ret = {'otp_secret': user.otp_secret, 'otp_uri': user.get_totp_uri()}
        return {'data': {'type': 'otp', 'id': '0', 'attributes': json_ret}}, 201


class GroupsList(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('groups_infos_all')
    @api.marshal_with(groups_fields_get_many)
    def get(self):
        """
        Get groups list
        """
        current_identity = import_user()

        groups = Group.query.all()
        groups_list = []

        for group in groups:
            if group.id in current_identity.groups or current_identity.admin:
                groups_list.append(group.__jsonapi__())

        return {'data': groups_list}

    @user_has('groups_create')
    @api.expect(groups_fields_post, validate=True)
    @api.marshal_with(groups_fields_get)
    def post(self):
        """
        Create group
        """
        data = request.get_json()['data']

        group = Group(name=data['attributes']['name'])

        try:
            group.abilities = list(id['id'] for id in data[
                                   'relationships']['abilities']['data'])
        except KeyError:
            pass

        try:
            group.users = list(id['id'] for id in data[
                'relationships']['users']['data'])
        except KeyError:
            pass

        db.session.add(group)
        db.session.commit()

        return {'data': group.__jsonapi__()}, 201


class Groups(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('groups_infos')
    @api.marshal_with(groups_fields_get)
    def get(self, id):
        """
        Get group
        """
        group = Group.query.get(id)

        current_identity = import_user()

        if not group:
            api.abort(code=404, message='Group not found')

        if id in current_identity.groups or current_identity.admin:
            return {'data': group.__jsonapi__()}
        else:
            api.abort(code=403, message='You do not have access')

    @user_has('groups_update')
    @api.expect(groups_fields_put, validate=True)
    @api.marshal_with(groups_fields_get)
    def put(self, id):
        """
        Update group
        """
        group = Group.query.get(id)

        if not group:
            api.abort(code=404, message='Group not found')

        data = request.get_json()['data']

        if 'name' in data['attributes']:
            group.name = data['attributes']['name']

        try:
            group.abilities = list(id['id'] for id in data[
                                   'relationships']['abilities']['data'])
        except KeyError:
            pass

        try:
            group.users = list(id['id'] for id in data[
                'relationships']['users']['data'])
        except KeyError:
            pass

        if len(data) > 0:
            db.session.commit()

        return {'data': group.__jsonapi__()}

    @user_has('groups_delete')
    def delete(self, id):
        """
        Delete group
        """
        group = Group.query.get(id)

        if not group:
            api.abort(code=404, message='Group not found')

        db.session.delete(group)
        db.session.commit()

        return {}, 204


class AbilitiesList(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('abilities_infos_all')
    @api.marshal_with(abilities_fields_get_many)
    def get(self):
        """
        Get abilities list
        """
        abilities = Ability.query.all()
        abilities_list = []

        for ability in abilities:
            abilities_list.append(ability.__jsonapi__())

        return {'data': abilities_list}


class Abilities(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('abilities_infos')
    @api.marshal_with(abilities_fields_get)
    def get(self, id):
        """
        Get ability
        """
        ability = Ability.query.get(id)

        if not ability:
            api.abort(code=404, message='Ability not found')

        return {'data': ability.__jsonapi__()}

    @user_has('abilities_update')
    @api.expect(abilities_fields_put, validate=True)
    @api.marshal_with(abilities_fields_get)
    def put(self, id):
        """
        Update ability
        """
        ability = Ability.query.get(id)

        data = request.get_json()['data']

        try:
            if len(data['relationships']['groups']['data']) >= 0:
                ability.groups = list(id['id'] for id in data[
                                      'relationships']['groups']['data'])
                db.session.commit()
        except KeyError:
            pass

        return {'data': ability.__jsonapi__()}


##################
# New API Requests #
##################

class RequestsList(Resource):
    decorators = [jwt_required, otp_confirmed]

    @api.marshal_with(requests_fields_get_many)
    def get(self):
        """
        Get requests list
        """
        current_identity = import_user()

        requests = Request.query.all()
        requests_list = []

        for req in requests:
            if req.id in current_identity.requests or current_identity.admin:
                requests_list.append(req.__jsonapi__())

        return {'data': requests_list}

    #@api.expect(requests_fields_post, validate=True)
    @api.marshal_with(requests_fields_get)
    def post(self):
        """
        Create request
        """
        data = request.get_json()['data']

        req = Request(message=data['attributes']['message'])
        req.action = data['attributes']['action']
        req.status = data['attributes']['status']
        req.meta_data = data['attributes']['meta_data']
        #req.users = list('1',)
        if 'relationships' in data:
            try:
                req.users = list(id['id'] for id in data[
                    'relationships']['users']['data'])
            except KeyError:
                pass
        else:
            current_identity = import_user()
            req.users = list(str(current_identity.id),)

        db.session.add(req)
        db.session.commit()

        mail_message = 'User:' + str(
            req.__jsonapi__()['relationships']['users']['data'][0]['attributes']['username']) + ' Data: ' + str(
            req.__jsonapi__()['attributes'])
        lgw.send_request(data['attributes']['message'], mail_message)

        return {'data': req.__jsonapi__()}, 201


class Requests(Resource):
    decorators = [jwt_required, otp_confirmed]

    @api.marshal_with(requests_fields_get)
    def get(self, id):
        """
        Get request
        """
        req = Request.query.get(id)

        if not req:
            api.abort(code=404, message='Request not found')

        return {'data': req.__jsonapi__()}

    @api.expect(requests_fields_put, validate=True)
    @api.marshal_with(requests_fields_get)
    def put(self, id):
        """
        Update request
        """
        req = Request.query.get(id)

        if not req:
            api.abort(code=404, message='Request not found')

        data = request.get_json()['data']

        if 'message' in data['attributes']:
            req.message = data['attributes']['message']
        if 'status' in data['attributes']:
            req.status = data['attributes']['status']
        req.changed_on = datetime.datetime.now()

        try:
            req.users = list(id['id'] for id in data[
                'relationships']['users']['data'])
        except KeyError:
            pass

        if len(data) > 0:
            db.session.commit()

        mail_message = 'User:' + str(
            req.__jsonapi__()['relationships']['users']['data'][0]['attributes']['username']) + ' Data: ' + str(
            req.__jsonapi__()['attributes'])
        lgw.send_request(data['attributes']['message'], mail_message)

        return {'data': req.__jsonapi__()}


##################
# Other API #
##################
class LXDConfig(Resource):
    decorators = [jwt_required, otp_confirmed]

    #@user_has('lxd_config')
    #@api.marshal_with(lxdconfig_fields_get)
    def get(self):
        """
        Get LXD config
        :return data
        """

        current_identity = import_user()
        data = {}

        if current_identity.admin:
            Config = configparser.ConfigParser()
            try:
                Config.read('lxdconfig.conf')
                data['endpoint'] = Config['remote']['endpoint']
                data['cert_crt'] = Config['remote']['cert_crt']
                data['cert_key'] = Config['remote']['cert_key']
                data['verify'] = Config['remote']['verify']

                if 'smtp' in Config:
                    data['smtp'] = {}
                    data['smtp']['enabled'] = Config['smtp']['enabled']
                    data['smtp']['sender'] = Config['smtp']['sender']
                    data['smtp']['recipient'] = Config['smtp']['recipient']
                    data['smtp']['server'] = Config['smtp']['server']
                    data['smtp']['port'] = Config['smtp']['port']
                    data['smtp']['login'] = Config['smtp']['login']
                    data['smtp']['password'] = Config['smtp']['password']

                if 'price' in Config:
                    print(Config['price']['enabled'])
                    data['price'] = {}
                    data['price']['periodes'] = {}
                    data['price']['enabled'] = Config['price']['enabled']
                    data['price']['cpu'] = Config['price']['cpu']
                    data['price']['memory'] = Config['price']['memory']
                    data['price']['disk'] = Config['price']['disk']
                    data['price']['periodes']['month'] = Config['price']['periodes.month']
                    data['price']['periodes']['months'] = Config['price']['periodes.months']
                    data['price']['periodes']['halfyear'] = Config['price']['periodes.halfyear']
                    data['price']['periodes']['year'] = Config['price']['periodes.year']
                    data['price']['periodes']['years'] = Config['price']['periodes.years']
                #except:
                    #data['price'] = None
                #    print(data)

                if 'storage' in Config:
                    data['storage'] = {}
                    data['storage']['enabled'] = Config['storage']['enabled']
                    data['storage']['pool_name'] = Config['storage']['pool_name']

                    #data['storage'] = None

                data['production_name'] = Config['app']['production_name']
            except Exception as e:
                api.abort(code=404, message='Error when read config file.')

            return {'data': {'attributes': data, 'type': 'lxdconfig', 'id': '1'}}

        else:
            Config = configparser.ConfigParser()
            try:
                Config.read('lxdconfig.conf')
                if 'smtp' in Config:
                    data['smtp'] = {}
                    data['smtp']['enabled'] = Config['smtp']['enabled']

                if 'price' in Config:
                    print(Config['price']['enabled'])
                    data['price'] = {}
                    data['price']['periodes'] = {}
                    data['price']['enabled'] = Config['price']['enabled']
                    data['price']['cpu'] = Config['price']['cpu']
                    data['price']['memory'] = Config['price']['memory']
                    data['price']['disk'] = Config['price']['disk']
                    data['price']['periodes']['month'] = Config['price']['periodes.month']
                    data['price']['periodes']['months'] = Config['price']['periodes.months']
                    data['price']['periodes']['halfyear'] = Config['price']['periodes.halfyear']
                    data['price']['periodes']['year'] = Config['price']['periodes.year']
                    data['price']['periodes']['years'] = Config['price']['periodes.years']

                if 'storage' in Config:
                    data['storage'] = {}
                    data['storage']['enabled'] = Config['storage']['enabled']
                    data['storage']['pool_name'] = Config['storage']['pool_name']

                    # data['storage'] = None

                data['production_name'] = Config['app']['production_name']
            except Exception as e:
                api.abort(code=404, message='Error when read config file.')

            return {'data': {'attributes': data, 'type': 'lxdconfig', 'id': '1'}}

        api.abort(code=404, message='You has not admin privileges')


    @user_has('lxd_config')
    @api.marshal_with(lxdconfig_fields_get)
    #@api.expect(lxdconfig_fields_post, validate=True)
    def post(self):
        """
        Set LXD config
        :return status code
        """
        current_identity = import_user()

        data = request.get_json()
        #print(data)

        if current_identity.admin:

            Config = configparser.ConfigParser()

            cfgfile = open('lxdconfig.conf', 'w')
            Config.add_section('local')
            Config.add_section('remote')
            Config.set('remote', 'endpoint', data['endpoint'])
            Config.set('remote', 'cert_crt', data['cert_crt'])
            Config.set('remote', 'cert_key', data['cert_key'])
            Config.set('remote', 'verify', data['verify'])

            Config.add_section('smtp')
            Config.set('smtp', 'enabled', str(data['smtp']['enabled']))
            Config.set('smtp', 'sender', data['smtp']['sender'])
            Config.set('smtp', 'recipient', data['smtp']['recipient'])
            Config.set('smtp', 'server', data['smtp']['server'])
            Config.set('smtp', 'port', data['smtp']['port'])
            Config.set('smtp', 'login', data['smtp']['login'])
            Config.set('smtp', 'password', data['smtp']['password'])

            Config.add_section('app')
            Config.set('app', 'production_name', data['production_name'])

            Config.add_section('price')
            #if data['price']['enabled']:
            Config.set('price', 'enabled', str(data['price']['enabled']))
            Config.set('price', 'cpu', data['price']['cpu'])
            Config.set('price', 'memory', data['price']['memory'])
            Config.set('price', 'disk', data['price']['disk'])
            Config.set('price', 'periodes.month', data['price']['periodes']['month'])
            Config.set('price', 'periodes.months', data['price']['periodes']['months'])
            Config.set('price', 'periodes.halfyear', data['price']['periodes']['halfyear'])
            Config.set('price', 'periodes.year', data['price']['periodes']['year'])
            Config.set('price', 'periodes.years', data['price']['periodes']['years'])

            Config.add_section('storage')
            #if data['storage']['enabled']:
            Config.set('storage', 'enabled', str(data['storage']['enabled']))
            Config.set('storage', 'pool_name', data['storage']['pool_name'])

            Config.write(cfgfile)
            cfgfile.close()

        return {}, 200


class LXDCerts(Resource):
    decorators = [jwt_required, otp_confirmed]
    @user_has('lxd_certs')
    @api.marshal_with(lxdcerts_fields_get)
    @api.expect(lxdcerts_fields_post, validate=True)
    def post(self):
        """
        Update LXD connection certificates
        :return status code
        """
        current_identity = import_user()

        data = request.get_json()

        config = configparser.ConfigParser()

        try:
            config.read('lxdconfig.conf')
        except Exception as e:
            print('wrong config file')

        if current_identity.admin:
            if data['cert_crt']:
                f = open(config['remote']['cert_crt'], 'w')
                f.write(data['cert_crt'])
                f.close()

            if data['cert_key']:
                f = open(config['remote']['cert_key'], 'w')
                f.write(data['cert_key'])
                f.close()

        return {}, 200
