#!/usr/bin/env python
# -*- coding: utf-8 -*-
from functools import wraps
from werkzeug.exceptions import Forbidden
from .models import *
# from flask_jwt_extended.view_decorators import _decode_jwt_from_request
from flask_jwt_extended import verify_jwt_in_request, get_jwt_claims
from lgw import lxd_api_get


def import_user():
    """
    Get user identity from json web token
    :return: current_identity
    """

    try:
        from flask_jwt_extended import get_jwt_identity
        current_identity = User.query.get(int(get_jwt_identity()))
        return current_identity
    except ImportError:
        raise ImportError(
            'User argument not passed')


def populate_containers_table():
    """
    Search for new or deleted containers and update their status in local database
    """

    all = []
    try:
        res = lxd_api_get('containers')
        for c in res.json()['metadata']:
            all.append(c[16:])  # get container name from api url
    except Exception as e:
        print(e)

    current_containers_list = tuple(all)
    database_containers_list = [str(i.name) for i in Container.query.all()]

    # Removing old containers from database
    for ct in database_containers_list:
        if not ct in current_containers_list:
            container = Container.query.filter_by(name=ct).first()
            db.session.delete(container)

    # Adding new containers to database
    for ct in current_containers_list:
        if not ct in database_containers_list:
            container = Container(name=ct)
            db.session.add(container)

    db.session.commit()


def user_has(ability, get_user=import_user):
    """
    Takes an ability (a string name of either a role or an ability) and returns the function if the user has that ability
    :param ability:
    :param get_user:
    :return: wrapper:
    """

    def wrapper(func):
        @wraps(func)
        def inner(*args, **kwargs):
            desired_ability = Ability.query.filter_by(
                name=ability).first()
            user_abilities = []
            current_identity = get_user()
            for group in current_identity._groups:
                user_abilities += group.abilities
            if desired_ability.id in user_abilities or current_identity.admin:
                return func(*args, **kwargs)
            else:
                raise Forbidden("You do not have access")
        return inner
    return wrapper


def otp_confirmed(fn):
    """
    If you decorate a vew with this, it will ensure that the requester has a
    valid JWT before calling the actual view. This does check if otp is confirmed
    :param fn: The view function to decorate
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):
        # jwt_data = _decode_jwt_from_request(request_type='access')
        # print(jwt_data)
        verify_jwt_in_request()
        claims = get_jwt_claims()
        if claims['otp_confirmed'] == False:
            raise Forbidden("You do not have access")
        else:
            return fn(*args, **kwargs)
    return wrapper

