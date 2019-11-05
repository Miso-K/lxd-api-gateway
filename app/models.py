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


def _container_find(c):
    container = Container.query.get(c)
    if not(container):
        raise ContainerDoesntExist(c)
    return container


def _request_find(r):
    request = Request.query.get(r)
    if not(request):
        raise RequestDoesntExist(r)
    return request


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

user_container_table = db.Table(
    'user_container',
    db.Column(
        'user_id',
        db.Integer,
        db.ForeignKey('users.id')
    ),
    db.Column(
        'container_id',
        db.Integer,
        db.ForeignKey('containers.id')
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
    language = db.Column(db.String(20), default='English')
    _groups = db.relationship(
        'Group',
        secondary=user_group_table
    )
    groups = association_proxy(
        '_groups',
        'id',
        creator=_group_find
    )
    _containers = db.relationship(
        'Container',
        secondary=user_container_table,
    )
    containers = association_proxy(
        '_containers',
        'id',
        creator=_container_find
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
        containers=None,
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
        if containers and isinstance(containers, list):
            self.containers = [container for container in containers]
        elif containers and isinstance(containers, int):
            self.containers = [containers]
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

    def add_containers(self, *containers):
        self.containers.extend(
            [container for container in containers if container not in self.containers])

    def remove_containers(self, *containers):
        self.containers = [
            container for container in self.containers if container not in containers]

    def __jsonapi__(self, group=None):
        _json = {
            'type': 'users',
            'id': self.id,
            'attributes': {
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
        }

        if group == 'flat':
            return _json

        _json['relationships'] = {}
        _json['relationships']['groups'] = {}
        _json['relationships']['containers'] = {}
        _json['relationships']['requests'] = {}

        _json['relationships']['groups']['data'] = [
            group.__jsonapi__('flat') for group in self._groups]
        _json['relationships']['containers']['data'] = [
            container.__jsonapi__('flat') for container in self._containers]
        _json['relationships']['requests']['data'] = [
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
            'attributes': {
                'name': self.name,
            }
        }

        if group == 'flat':
            return _json

        _json['relationships'] = {}
        _json['relationships']['abilities'] = {}
        _json['relationships']['users'] = {}

        _json['relationships']['abilities']['data'] = [
            ability.__jsonapi__('flat') for ability in self._abilities]
        _json['relationships']['users']['data'] = [
            user.__jsonapi__('flat') for user in self._users]

        return _json

    def __repr__(self):
        return '<Group %r>' % self.id


class Ability(db.Model):
    __tablename__ = 'abilities'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), unique=True)
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
        groups=None
    ):

        self.name = name

        if groups and isinstance(groups, list):
            self.groups = [group for group in groups]
        elif groups and isinstance(groups, int):
            self.groups = [groups]

    def __jsonapi__(self, group=None):
        _json = {
            'type': 'abilities',
            'id': self.id,
            'attributes': {
                'name': self.name
            }
        }

        if group == 'flat':
            return _json

        _json['relationships'] = {}
        _json['relationships']['groups'] = {}

        _json['relationships']['groups']['data'] = [
            group.__jsonapi__('flat') for group in self._groups]

        return _json

    def __repr__(self):
        return '<Ability %r>' % self.id


class Container(db.Model):
    __tablename__ = 'containers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True)
    _users = db.relationship(
        'User',
        secondary=user_container_table,
    )
    users = association_proxy(
        '_users',
        'id',
        creator=_user_find
    )

    def __init__(
        self,
        name=None,
        users=None
    ):

        self.name = name

        if users and isinstance(users, list):
            self.users = [user for user in users]
        elif users and isinstance(users, int):
            self.users = [users]

    def __jsonapi__(self, group=None):
        _json = {
            'type': 'containers',
            'id': self.id,
            'attributes': {
                'name': self.name
            }
        }

        if group == 'flat':
            return _json

        _json['relationships'] = {}
        _json['relationships']['users'] = {}

        _json['relationships']['users']['data'] = [
            user.__jsonapi__('flat') for user in self._users]

        return _json

    def __repr__(self):
        return '<Container %r>' % self.id


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
            'attributes': {
                'action': self.action,
                'message': self.message,
                'meta_data': self.meta_data,
                'status': self.status,
                'created_on': self.created_on,
                'changed_on': self.changed_on
            }
        }

        if group == 'flat':
            return _json

        _json['relationships'] = {}
        _json['relationships']['users'] = {}

        _json['relationships']['users']['data'] = [
            user.__jsonapi__('flat') for user in self._users]

        return _json

    def __repr__(self):
        return '<Request %r>' % self.id
