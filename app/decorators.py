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


def populate_instances_table():
    """
    Search for new or deleted instances and update their status in local database
    """

    database_lxdservers_list = Server.query.all()
    for lxdserver in database_lxdservers_list:
        all = []
        try:
            res = lxd_api_get(lxdserver, 'instances')
            for c in res.json()['metadata']:
                all.append(c[15:])  # get instance name from api url
        except Exception as e:
            print(e)

        current_instances_list = tuple(all)
        database_instances_list = Instance.query.filter_by(location=lxdserver.name)
        database_instances_list_names = [str(i.name) for i in database_instances_list]

        # Removing old instances from database
        for inst in database_instances_list:
            if not inst.name in current_instances_list:
                db.session.delete(inst)
                db.session.commit()
            if len(inst.servers) == 0:
                db.session.delete(inst)
                db.session.commit()

        # Adding new instances to database
        for cinst in current_instances_list:
            if not cinst in database_instances_list_names:
                instance = Instance()
                instance.name = cinst
                instance.location = lxdserver.name
                db.session.add(instance)
                db.session.commit()

                lxdserver.instances.append(instance.id)
                db.session.commit()

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
            if current_identity.admin or desired_ability.id in user_abilities:
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

