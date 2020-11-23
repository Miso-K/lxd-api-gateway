#!/usr/bin/env python
# -*- coding: utf-8 -*-

from app import db, redis_store
from app.exceptions import *
from passlib.apps import custom_app_context as pwd_context
from sqlalchemy.ext.associationproxy import association_proxy
import datetime
import os
import base64
import onetimepass
import configparser


def _user_find(u):
    user = User.query.get(u)
    if not(user):
        raise UserDoesntExist(u)
    return user


def _group_find(g):
    group = Group.query.get(g)
    if not(group):
        raise GroupDoesntExist(g)
    return group


def _ability_find(a):
    ability = Ability.query.get(a)
    if not(ability):
        raise AbilityDoesntExist(a)
    return ability


def _instance_find(c):
    instance = Instance.query.get(c)
    if not(instance):
        raise InstanceDoesntExist(c)
    return instance


def _request_find(r):
    request = Request.query.get(r)
    if not(request):
        raise RequestDoesntExist(r)
    return request


def _server_find(s):
    server = Request.query.get(s)
    if not (server):
        raise ServerDoesntExist(s)
    return server


user_group_table = db.Table(
    'user_group',
    db.Column(
        'user_id',
        db.Integer,
        db.ForeignKey('users.id')
    ),
    db.Column(
        'group_id',
        db.Integer,
        db.ForeignKey('groups.id')
    )
)

group_ability_table = db.Table(
    'group_ability',
    db.Column(
        'group_id',
        db.Integer,
        db.ForeignKey('groups.id')
    ),
    db.Column(
        'ability_id',
        db.Integer,
        db.ForeignKey('abilities.id')
    )
)

user_instance_table = db.Table(
    'user_instance',
    db.Column(
        'user_id',
        db.Integer,
        db.ForeignKey('users.id')
    ),
    db.Column(
        'instance_id',
        db.Integer,
        db.ForeignKey('instances.id')
    )
)

user_request_table = db.Table(
    'user_request',
    db.Column(
        'user_id',
        db.Integer,
        db.ForeignKey('users.id')
    ),
    db.Column(
        'request_id',
        db.Integer,
        db.ForeignKey('requests.id')
    )
)

server_instance_table = db.Table(
    'server_instance',
    db.Column(
        'server_id',
        db.Integer,
        db.ForeignKey('servers.id')
    ),
    db.Column(
        'instance_id',
        db.Integer,
        db.ForeignKey('instances.id')
    )
)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    admin = db.Column(db.Boolean, default=False, nullable=False)
    name = db.Column(db.String(255))
    username = db.Column(db.String(60), unique=True, nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(255))
    address = db.Column(db.String(255))
    city = db.Column(db.String(120))
    country = db.Column(db.String(120))
    postal_code = db.Column(db.String(20))
    ico = db.Column(db.String(10))
    ic_dph = db.Column(db.String(10))
    dic = db.Column(db.String(10))
    password = db.Column(db.String(100), nullable=False)
    otp_type = db.Column(db.String(10))
    otp_secret = db.Column(db.String(20))
    language = db.Column(db.String(20), default='en')
    _groups = db.relationship(
        'Group',
        secondary=user_group_table
    )
    groups = association_proxy(
        '_groups',
        'id',
        creator=_group_find
    )
    _instances = db.relationship(
        'Instance',
        secondary=user_instance_table,
    )
    instances = association_proxy(
        '_instances',
        'id',
        creator=_instance_find
    )
    _requests = db.relationship(
        'Request',
        secondary=user_request_table,
    )
    requests = association_proxy(
        '_requests',
        'id',
        creator=_request_find
    )

    def __init__(
        self,
        admin=False,
        name=None,
        username=None,
        registered_on=None,
        email=None,
        phone=None,
        address=None,
        city=None,
        country=None,
        postal_code=None,
        ico=None,
        ic_dph=None,
        dic=None,
        password=None,
        otp_type=None,
        otp_secret=None,
        language=None,
        groups=None,
        instances=None,
        requests=None
    ):

        self.admin = admin
        self.name = name
        self.username = username
        self.registered_on = datetime.datetime.now()
        self.email = email
        self.phone = phone
        self.address = address
        self.city = city
        self.country = country
        self.postal_code = postal_code
        self.ico = ico
        self.ic_dph = ic_dph
        self.dic = dic
        self.password = password
        self.otp_type = otp_type
        self.otp_secret = otp_secret
        self.language = language

        if groups and isinstance(groups, list):
            self.groups = [group for group in groups]
        elif groups and isinstance(groups, int):
            self.groups = [groups]
        if instances and isinstance(instances, list):
            self.instances = [instance for instance in instances]
        elif instances and isinstance(instances, int):
            self.instances = [instances]
        if requests and isinstance(requests, list):
            self.requests = [req for req in requests]
        elif requests and isinstance(requests, int):
            self.requests = [requests]

    def hash_password(self, password):
        self.password = pwd_context.hash(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password)

    def add_totp_secret(self):
        if self.otp_secret is None:
            # generate a random secret
            self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')

    def get_totp_uri(self):
        config = configparser.ConfigParser()
        production_name = 'lxdmanager.com'
        try:
            config.read('lxdconfig.conf')
            production_name = config['app']['production_name']
        finally:
            return 'otpauth://totp/2FA-{0}:{1}?secret={2}&issuer=2FA-{0}' \
                .format(production_name, self.username, self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)

    def has_totp_enabled(self):
        if self.otp_secret is None:
            return False
        else:
            return True

    def get_otp_type(self):
        return self.otp_type

    def create_eotp(self):
        #if self.otp_type == 'email':
        secret = base64.b32encode(os.urandom(10)).decode('utf-8')[2:8]
        s_hash = pwd_context.hash(secret)
        redis_store.set('eotp:' + self.username, s_hash, 300)
        return secret

    def verify_eotp(self, secret):
        r_hash = redis_store.get('eotp:' + self.username)
        redis_store.delete('eotp:' + self.username)
        return pwd_context.verify(secret, r_hash)

    def add_instances(self, *instances):
        self.instances.extend(
            [instance for instance in instances if instance not in self.instances])

    def remove_instances(self, *instances):
        self.instances = [
            instance for instance in self.instances if instance not in instances]

    def __jsonapi__(self, group=None):
        _json = {
            'type': 'users',
            'id': self.id,
            'admin': self.admin,
            'name': self.name,
            'username': self.username,
            'registered_on': self.registered_on,
            'email': self.email,
            'phone': self.phone,
            'address': self.address,
            'city': self.city,
            'country': self.country,
            'postal_code': self.postal_code,
            'ico': self.ico,
            'ic_dph': self.ic_dph,
            'dic': self.dic,
            'language': self.language,
            'otp_enabled': self.has_totp_enabled(),
            'otp_type': self.otp_type
        }

        if group == 'flat':
            return _json

        _json['relationships'] = {}

        _json['relationships']['groups'] = [
            group.__jsonapi__('flat') for group in self._groups]
        _json['relationships']['instances'] = [
            instance.__jsonapi__('flat') for instance in self._instances]
        _json['relationships']['requests'] = [
            req.__jsonapi__('flat') for req in self._requests]

        return _json

    def __repr__(self):
        return '<User %r>' % self.id


class Group(db.Model):
    __tablename__ = 'groups'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True)
    _abilities = db.relationship(
        'Ability',
        secondary=group_ability_table
    )
    abilities = association_proxy(
        '_abilities',
        'id',
        creator=_ability_find
    )
    _users = db.relationship(
        'User',
        secondary=user_group_table,
    )
    users = association_proxy(
        '_users',
        'id',
        creator=_user_find
    )

    def __init__(
        self,
        name=None,
        abilities=None,
        users=None
    ):

        self.name = name

        if abilities and isinstance(abilities, list):
            self.abilities = [ability for ability in abilities]
        elif abilities and isinstance(abilities, int):
            self.abilities = [abilities]

        if users and isinstance(users, list):
            self.users = [user for user in users]
        elif users and isinstance(users, int):
            self.users = [users]

    def __jsonapi__(self, group=None):
        _json = {
            'type': 'groups',
            'id': self.id,
            'name': self.name
        }

        if group == 'flat':
            return _json

        _json['relationships'] = {}

        _json['relationships']['abilities'] = [
            ability.__jsonapi__('flat') for ability in self._abilities]
        _json['relationships']['users'] = [
            user.__jsonapi__('flat') for user in self._users]

        return _json

    def __repr__(self):
        return '<Group %r>' % self.id


class Ability(db.Model):
    __tablename__ = 'abilities'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), unique=False)
    category = db.Column(db.String(30), unique=False)
    _groups = db.relationship(
        'Group',
        secondary=group_ability_table
    )
    groups = association_proxy(
        '_groups',
        'id',
        creator=_group_find
    )

    def __init__(
        self,
        name=None,
        category=None,
        groups=None
    ):

        self.name = name
        self.category = category

        if groups and isinstance(groups, list):
            self.groups = [group for group in groups]
        elif groups and isinstance(groups, int):
            self.groups = [groups]

    def __jsonapi__(self, group=None):
        _json = {
            'type': 'abilities',
            'id': self.id,
            'name': self.name,
            'category': self.category
        }

        if group == 'flat':
            return _json

        _json['relationships'] = {}

        _json['relationships']['groups'] = [
            group.__jsonapi__('flat') for group in self._groups]

        return _json

    def __repr__(self):
        return '<Ability %r>' % self.id


class Instance(db.Model):
    __tablename__ = 'instances'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True)
    location = db.Column(db.String(255), unique=False)
    _users = db.relationship(
        'User',
        secondary=user_instance_table,
    )
    users = association_proxy(
        '_users',
        'id',
        creator=_user_find
    )
    _servers = db.relationship(
        'Server',
        secondary=server_instance_table,
    )
    servers = association_proxy(
        '_servers',
        'id',
        creator=_server_find
    )

    def __init__(
        self,
        name=None,
        location=None,
        users=None,
        servers=None
    ):

        self.name = name

        if users and isinstance(users, list):
            self.users = [user for user in users]
        elif users and isinstance(users, int):
            self.users = [users]
        if servers and isinstance(servers, list):
            self.servers = [server for server in servers]
        elif servers and isinstance(servers, int):
            self.servers = [servers]

    def __jsonapi__(self, group=None):
        _json = {
            'type': 'instances',
            'id': self.id,
            'name': self.name
        }

        if group == 'flat':
            return _json

        _json['relationships'] = {}

        _json['relationships']['users'] = [
            user.__jsonapi__('flat') for user in self._users]

        _json['relationships']['servers'] = [
            server.__jsonapi__('flat') for server in self._servers]

        return _json

    def __repr__(self):
        return '<Instance %r>' % self.id


class Request(db.Model):
    __tablename__ = 'requests'
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(255), unique=False)
    message = db.Column(db.String(255), unique=False)
    meta_data = db.Column(db.JSON, unique=False)
    status = db.Column(db.String(255), unique=False)
    created_on = db.Column(db.DateTime, nullable=False)
    changed_on = db.Column(db.DateTime)

    _users = db.relationship(
        'User',
        secondary=user_request_table,
    )
    users = association_proxy(
        '_users',
        'id',
        creator=_user_find
    )

    def __init__(
        self,
        action=None,
        message=None,
        meta_data=None,
        status=None,
        created_on=None,
        changed_on=None,
        users=None
    ):

        self.action = action
        self.message = message
        self.meta_data = meta_data
        self.status = status
        self.created_on = datetime.datetime.now()
        self.changed_on = changed_on

        if users and isinstance(users, list):
            self.users = [user for user in users]
        elif users and isinstance(users, int):
            self.users = [users]

    def __jsonapi__(self, group=None):
        _json = {
            'type': 'requests',
            'id': self.id,
            'action': self.action,
            'message': self.message,
            'meta_data': self.meta_data,
            'status': self.status,
            'created_on': self.created_on,
            'changed_on': self.changed_on
        }

        if group == 'flat':
            return _json

        _json['relationships'] = {}

        _json['relationships']['users'] = [
            user.__jsonapi__('flat') for user in self._users]

        return _json

    def __repr__(self):
        return '<Request %r>' % self.id


class Server(db.Model):
    __tablename__ = 'servers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True)
    address = db.Column(db.String(255), unique=True)
    exec_address = db.Column(db.String(255), unique=False)
    key_private = db.Column(db.String(255), unique=True)
    key_public = db.Column(db.String(255), unique=True)
    verify = db.Column(db.String(255))

    _instances = db.relationship(
        'Instance',
        secondary=server_instance_table,
    )
    instances = association_proxy(
        '_instances',
        'id',
        creator=_instance_find
    )

    def __init__(
        self,
        name=None,
        address=None,
        exec_address=None,
        key_private=None,
        key_public=None,
        verify=None,
        instances=None
    ):

        self.name = name

        if instances and isinstance(instances, list):
            self.instances = [instance for instance in instances]
        elif instances and isinstance(instances, int):
            self.instances = [instances]

    def get_as_relationships(self):
        relationships = {
            'servers': [
                {
                    'id': self.id,
                    'name': self.name
                }
            ]
        }
        return relationships

    def get_as_relationships_exec(self):
        relationships = {
            'servers': [
                {
                    'id': self.id,
                    'name': self.name,
                    'exec_address': self.exec_address
                }
            ]
        }
        return relationships

    def __jsonapi__(self, group=None):
        _json = {
            'type': 'servers',
            'id': self.id,
            'name': self.name,
            'address': self.address,
            'exec_address': self.exec_address,
            'verify': self.verify
            #'key_private': self.key_private, # do not send private key info in REST API
            #'key_public': self.key_public,
        }

        if group == 'flat':
            return _json

        if group == 'redis':
            _json['key_private'] = self.key_private
            _json['key_public'] = self.key_public
            return _json

        _json['relationships'] = {}

        _json['relationships']['instances'] = [
            instance.__jsonapi__('flat') for instance in self._instances]

        return _json

    def __repr__(self):
        return '<Server %r>' % self.id

