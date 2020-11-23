#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import request
from flask_restplus import Resource
from flask_jwt_extended import jwt_required, create_access_token, \
    jwt_refresh_token_required, create_refresh_token, get_jti, get_raw_jwt
from app import app
from .decorators import *
from .fields.auth import *
from .fields.users import *
from .fields.groups import *
from .fields.abilities import *
from .fields.requests import *
from .fields.lxdconfig import *
import lgw
import configparser
# import time


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

        user_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)

        user = User.query.filter_by(username=username).first()

        if not user or not user.verify_password(password):
            app.logger.info('User: %s login fail', username)
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
            redis_store.set('access_jti:' + user_ip + access_jti, 'false', app.config['OTP_ACCESS_TOKEN_EXPIRES'])
            # print(redis_store.get(access_jti) + ' ' + access_jti)
            app.logger.info('User: %s logged, waiting for OTP', username)
            return ret

        access_token = create_access_token(identity=user, fresh=True)
        refresh_token = create_refresh_token(identity=user)
        access_jti = get_jti(encoded_token=access_token)
        refresh_jti = get_jti(encoded_token=refresh_token)
        redis_store.set('access_jti:' + user_ip + access_jti, 'false', app.config['ACCESS_TOKEN_EXPIRES'])
        redis_store.set('refresh_jti:' + user_ip + refresh_jti, 'false', app.config['REFRESH_TOKEN_EXPIRES'])
        ret = {'access_token': access_token,
               'refresh_token': refresh_token}
        app.logger.info('User: %s logged in', username)
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

        user_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)

        # revoke otp_access_token
        jti = get_raw_jwt()['jti']
        redis_store.set('access_jti:' + user_ip + jti, 'true', app.config['OTP_ACCESS_TOKEN_EXPIRES'])

        if user.get_otp_type() == 'totp':
            if not user.verify_totp(secret):
                app.logger.info('User: %s incorrect secret code', user.username)
                api.abort(code=401, message='Incorrect secret code')
        elif user.get_otp_type() == 'email':
            if not user.verify_eotp(secret):
                app.logger.info('User: %s incorrect secret code', user.username)
                api.abort(code=401, message='Incorrect secret code')
        else:
            app.logger.info('User: %s incorrect OTP type', user.username)
            api.abort(code=401, message='Incorrect otp type')

        user.otp_confirmed = True

        access_token = create_access_token(identity=user, fresh=True)
        refresh_token = create_refresh_token(identity=user)
        access_jti = get_jti(encoded_token=access_token)
        refresh_jti = get_jti(encoded_token=refresh_token)
        redis_store.set('access_jti:' + user_ip + access_jti, 'false', app.config['ACCESS_TOKEN_EXPIRES'])
        redis_store.set('refresh_jti:' + user_ip + refresh_jti, 'false', app.config['REFRESH_TOKEN_EXPIRES'])
        ret = {'access_token': access_token,
               'refresh_token': refresh_token}
        app.logger.info('User: %s logged in', user.username)
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
        user_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        user.otp_confirmed = True
        access_token = create_access_token(identity=user, fresh=False)
        access_jti = get_jti(encoded_token=access_token)
        redis_store.set('access_jti:' + user_ip + access_jti, 'false', app.config['ACCESS_TOKEN_EXPIRES'])
        ret = {
            'access_token': access_token
        }
        app.logger.info('User: %s refresh token', user.username)
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
        user_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        if not jti:
            app.logger.info('User: %s token not found - Logout', import_user().username)
            api.abort(code=404, message='Token not found')
        redis_store.set('access_jti:' + user_ip + jti, 'true', app.config['ACCESS_TOKEN_EXPIRES'])
        app.logger.info('User: %s token revoked - Logout', import_user().username)
        return {"msg": "Access token revoked"}, 200


class UsersList(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('users_infos_all')
    @api.marshal_with(users_fields_get_many)
    def get(self):
        """
        Get users list
        """
        populate_instances_table()
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
        app.logger.debug('Create user data: %s', data)
        if User.query.filter_by(username=data['username']).first():
            app.logger.info('User: %s already exists', data['username'])
            api.abort(code=409, message='User already exists')

        user = User()

        user.username = data['username']
        user.name = data['name']
        user.hash_password(data['password'])

        if 'admin' in data and current_identity.admin:
            user.admin = data['admin']
        if 'email' in data:
            user.email = data['email']
        if 'phone' in data:
            user.phone = data['phone']
        if 'address' in data:
            user.address = data['address']
        if 'city' in data:
            user.city = data['city']
        if 'country' in data:
            user.country = data['country']
        if 'postal_code' in data:
            user.postal_code = data['postal_code']
        if 'ico' in data:
            user.ico = data['ico']
        if 'ic_dph' in data:
            user.ic_dph = data['ic_dph']
        if 'dic' in data:
            user.dic = data['dic']
        if 'language' in data:
            user.language = data['language']
        if 'otp_type' in data:
            if data['otp_type'] == 'none':
                user.otp_type = None
            else:
                user.otp_type = data['otp_type']

        try:
            user.groups = list(id['id'] for id in data['relationships']['groups'])
        except KeyError:
            pass

        try:
            user.instances = list(id['id'] for id in data['relationships']['instances'])
        except KeyError:
            pass

        db.session.add(user)
        db.session.commit()

        app.logger.info('User: %s created successfully by %s', user.username, import_user().username)
        return {'data': user.__jsonapi__()}, 201


class Users(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('users_infos')
    @api.marshal_with(users_fields_get)
    def get(self, id):
        """
        Get user
        """
        populate_instances_table()
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
            app.logger.info('User not found for update')
            api.abort(code=404, message='User not found')

        data = request.get_json()['data']
        #print(data)

        if 'admin' in data and current_identity.admin:
            user.admin = data['admin']
        if 'name' in data:
            user.name = data['name']
        if 'email' in data:
            user.email = data['email']
        if 'phone' in data:
            user.phone = data['phone']
        if 'address' in data:
            user.address = data['address']
        if 'city' in data:
            user.city = data['city']
        if 'country' in data:
            user.country = data['country']
        if 'postal_code' in data:
            user.postal_code = data['postal_code']
        if 'ico' in data:
            user.ico = data['ico']
        if 'ic_dph' in data:
            user.ic_dph = data['ic_dph']
        if 'dic' in data:
            user.dic = data['dic']
        if 'language' in data:
            user.language = data['language']

        if 'password' in data and current_identity.admin:
            user.hash_password(data['password'])

        try:
            user.groups = list(id['id'] for id in data[
                               'relationships']['groups'])
        except KeyError:
            pass

        try:
            user.instances = list(id['id'] for id in data[
                                   'relationships']['instances'])
        except KeyError:
            pass

        if len(data) > 0:
            db.session.commit()

        app.logger.info('User: %s updated successfully by %s', user.username, import_user().username)
        return {'data': user.__jsonapi__()}

    @user_has('users_delete')
    def delete(self, id):
        """
        Delete user
        """
        user = User.query.get(id)

        if not user:
            app.logger.info('User not found for delete')
            api.abort(code=404, message='User not found')

        db.session.delete(user)
        db.session.commit()

        app.logger.info('User: %s deleted successfully by %s', user.username, import_user().username)
        return {}, 204


class Me(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('me_infos')
    @api.marshal_with(users_fields_get)
    def get(self):
        """
        Get me
        """
        populate_instances_table()
        current_identity = import_user()
        return {'data': current_identity.__jsonapi__()}

    @user_has('me_update')
    #@api.expect(users_fields_put, validate=True)
    @api.marshal_with(users_fields_get)
    def put(self):
        """
        Update me
        """
        current_identity = import_user()
        user = User.query.get(current_identity.id)

        data = request.get_json()['data']

        if 'name' in data:
            user.name = data['name']
        if 'email' in data:
            user.email = data['email']
        if 'phone' in data:
            user.phone = data['phone']
        if 'address' in data:
            user.address = data['address']
        if 'city' in data:
            user.city = data['city']
        if 'country' in data:
            user.country = data['country']
        if 'postal_code' in data:
            user.postal_code = data['postal_code']
        if 'ico' in data:
            user.ico = data['ico']
        if 'ic_dph' in data:
            user.ic_dph = data['ic_dph']
        if 'dic' in data:
            user.dic = data['dic']
        if 'language' in data:
            user.language = data['language']
        if 'otp_type' in data:
            if data['otp_type'] == 'none':
                user.otp_type = None
            else:
                user.otp_type = data['otp_type']

        if 'cur_password' in data:
            cur_password = data['cur_password']
            #print('before verify')
            #print(data['attributes'])
            if 'new_password' in data and user.verify_password(cur_password):
                if data['new_password'] == data['confirm_password']:
                    user.hash_password(data['new_password'])
            else:
                app.logger.info('User: %s update with wrong password', user.username)
                api.abort(code=401, message='Incorrect user or password')

        # Not secure for user to change his group or instance

        if len(data) > 0:
            db.session.commit()

        app.logger.info('User: %s updated successfully', user.username)
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

    @user_has('me_otp_create')
    def post(self):
        """
        Generate totp secret
        User can set totp secret only once
        """
        current_identity = import_user()
        user = User.query.get(current_identity.id)

        if not user:
            app.logger.info('User not found when generate totp')
            api.abort(code=404, message='User not found')

        # if user has otp_secret do not create new
        if not user.otp_type:
            try:
                user.otp_type = 'totp'
                user.add_totp_secret()
            except Exception as e:
                print(e)
                app.logger.debug('Generate totp error: %s', e)
                app.logger.info('User: %s cant generate totp secret', user.username)
                api.abort(code=500, message='Can\'t generate totp secret')
        else:
            app.logger.info('User: %s has totp secret yet', user.username)
            api.abort(code=500, message='User has totp secret set')

        db.session.commit()
        json_ret = {'type': 'otp', 'otp_secret': user.otp_secret, 'otp_uri': user.get_totp_uri()}

        app.logger.info('User: %s generate totp successfully', user.username)
        return {'data': json_ret}, 201


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

        group = Group(name=data['name'])

        try:
            group.abilities = list(id['id'] for id in data[
                                   'relationships']['abilities'])
        except KeyError:
            pass

        try:
            group.users = list(id['id'] for id in data[
                'relationships']['users'])
        except KeyError:
            pass

        db.session.add(group)
        db.session.commit()

        app.logger.info('Group %s created successfully by %s', data['name'], import_user().username)
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

        if 'name' in data:
            group.name = data['name']

        try:
            group.abilities = list(id['id'] for id in data[
                                   'relationships']['abilities'])
        except KeyError:
            pass

        try:
            group.users = list(id['id'] for id in data[
                'relationships']['users'])
        except KeyError:
            pass

        if len(data) > 0:
            db.session.commit()

        app.logger.info('Group %s updated successfully by %s', group.name, import_user().username)
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

        app.logger.info('Group %s deleted successfully by %s', group.name, import_user().username)
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
            if len(data['relationships']['groups']) >= 0:
                ability.groups = list(id['id'] for id in data[
                                      'relationships']['groups'])
                db.session.commit()
        except KeyError:
            pass

        app.logger.info('Ability %s updated successfully by %s', ability.name, import_user().username)
        return {'data': ability.__jsonapi__()}


##################
# New API Requests #
##################

class RequestsList(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('requests_infos_all')
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
        #return requests_list

    @user_has('requests_create')
    #@api.expect(requests_fields_post, validate=True)
    @api.marshal_with(requests_fields_get)
    def post(self):
        """
        Create request
        """
        data = request.get_json()['data']
        #print(data)

        req = Request(message=data['message'])
        req.action = data['action']
        req.status = data['status']
        req.meta_data = data['meta_data']
        #req.users = list('1',)
        if 'relationships' in data:
            try:
                req.users = list(id['id'] for id in data[
                    'relationships']['users'])
            except KeyError:
                pass
        else:
            current_identity = import_user()
            req.users = list(str(current_identity.id),)

        db.session.add(req)
        db.session.commit()

        username = req.__jsonapi__()['relationships']['users'][0]['username']
        usermail = req.__jsonapi__()['relationships']['users'][0]['email']
        atr = req.__jsonapi__()

        details = ''
        for key, value in atr['meta_data'].items():
            details += str(key) + ': ' + str(value) + '<br>'

        mail_message = """\
                            <html>
                              <head></head>
                              <body>
                                """ + data['mail_message'] + """
                              </body>
                            </html>
                            """
        #print(mail_message)
        lgw.get_config()
        lgw.send_request(data['message'], mail_message, usermail)

        app.logger.info('Request created successfully by %s', import_user().username)
        return {'data': req.__jsonapi__()}, 201


class Requests(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('requests_infos')
    @api.marshal_with(requests_fields_get)
    def get(self, id):
        """
        Get request
        """
        req = Request.query.get(id)
        print(req.__jsonapi__())

        if not req:
            api.abort(code=404, message='Request not found')

        return {'data': req.__jsonapi__()}
        #return req.__jsonapi__()

    @user_has('requests_update')
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

        if 'message' in data:
            req.message = data['message']
        if 'status' in data:
            req.status = data['status']
        req.changed_on = datetime.datetime.now()

        try:
            req.users = list(id['id'] for id in data[
                'relationships']['users'])
        except KeyError:
            pass

        if len(data) > 0:
            db.session.commit()

        username = req.__jsonapi__()['relationships']['users'][0]['username']
        usermail = req.__jsonapi__()['relationships']['users'][0]['email']

        #mail_message = 'User:' + username + '/r/nData: ' + str(
        atr = req.__jsonapi__()

        details = ''
        for key, value in atr['meta_data'].items():
            details += str(key) + ': ' + str(value) + '<br>'

        mail_message = """\
                            <html>
                              <head></head>
                              <body>
                                """ + data['mail_message'] + """
                              </body>
                            </html>
                            """

        lgw.send_request(data['message'], mail_message, usermail)

        app.logger.info('Request updated successfully by %s', import_user().username)
        return {'data': req.__jsonapi__()}

    @user_has('requests_delete')
    def delete(self, id):
        """
        Delete request
        """
        req = Request.query.get(id)

        if not req:
            api.abort(code=404, message='Request not found')

        db.session.delete(req)
        db.session.commit()

        app.logger.info('Request deleted successfully by %s', import_user().username)
        return {}, 204


##################
# Other API #
##################
class LgwConfig(Resource):
    decorators = [jwt_required, otp_confirmed]

    @user_has('config_infos')
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
                data = {}
                for each_section in Config.sections():
                    data[each_section] = {}
                    for (each_key, each_val) in Config.items(each_section):
                        data[each_section][each_key] = each_val

            except Exception as e:
                api.abort(code=404, message='Error when read config file.')

            #return {'data': {'attributes': data, 'type': 'lxdconfig', 'id': '1'}}
            return {'data': data}

        else:
            Config = configparser.ConfigParser()
            try:
                Config.read('lxdconfig.conf')
                data = {}
                for each_section in Config.sections():
                    data[each_section] = {}
                    if each_section == 'remote':
                        continue
                    if each_section == 'smtp':
                        continue
                    for (each_key, each_val) in Config.items(each_section):
                        data[each_section][each_key] = each_val

                if 'smtp' in Config:
                    data['smtp'] = {}
                    data['smtp']['enabled'] = Config['smtp']['enabled']

            except Exception as e:
                api.abort(code=404, message='Error when read config file.')

            #return {'data': {'attributes': data, 'type': 'lxdconfig', 'id': '1'}}
            return {'data': data}

        api.abort(code=404, message='You has not access')


    @user_has('config_update')
    @api.marshal_with(lxdconfig_fields_get)
    @api.expect(lxdconfig_fields_post)
    def post(self):
        """
        Set LXD config
        :return status code
        """
        current_identity = import_user()

        data = request.get_json()
        #print(data)

        def updateconf(Config, section, option):
            if not Config.has_section(section):
                Config.add_section(section)

            if section in data:
                if option in data[section]:
                    Config.set(section, option, str(data[section][option]))

        if current_identity.admin and data:

            Config = configparser.ConfigParser()
            try:
                Config.read('lxdconfig.conf')

                updateconf(Config, 'smtp', 'enabled')
                updateconf(Config, 'smtp', 'notify_user')
                updateconf(Config, 'smtp', 'sender')
                updateconf(Config, 'smtp', 'recipient')
                updateconf(Config, 'smtp', 'server')
                updateconf(Config, 'smtp', 'port')
                updateconf(Config, 'smtp', 'login')
                updateconf(Config, 'smtp', 'password')

                updateconf(Config, 'app', 'production_name')

                updateconf(Config, 'price', 'enabled')
                updateconf(Config, 'price', 'cpu')
                updateconf(Config, 'price', 'memory')
                updateconf(Config, 'price', 'disk')
                updateconf(Config, 'price', 'discount_month')
                updateconf(Config, 'price', 'discount_months')
                updateconf(Config, 'price', 'discount_halfyear')
                updateconf(Config, 'price', 'discount_year')
                updateconf(Config, 'price', 'discount_years')

                updateconf(Config, 'storage', 'enabled')
                updateconf(Config, 'storage', 'pool_name')
                updateconf(Config, 'storage', 'total_size')
                updateconf(Config, 'storage', 'limits_unit')
                updateconf(Config, 'storage', 'limits_unit_show')
                updateconf(Config, 'storage', 'limits_min')
                updateconf(Config, 'storage', 'limits_max')
                updateconf(Config, 'storage', 'limits_step')

                updateconf(Config, 'memory', 'limits_unit')
                updateconf(Config, 'memory', 'limits_unit_show')
                updateconf(Config, 'memory', 'limits_min')
                updateconf(Config, 'memory', 'limits_max')
                updateconf(Config, 'memory', 'limits_step')

                updateconf(Config, 'cpu', 'limits_min')
                updateconf(Config, 'cpu', 'limits_max')
                updateconf(Config, 'cpu', 'limits_step')

            except Exception as e:
                print('exception', e)
                return {}, 500

            cfgfile = open('lxdconfig.conf', 'w')
            Config.write(cfgfile)
            cfgfile.close()

        app.logger.info('LGW config updated successfully by %s', import_user().username)
        return {}, 200

