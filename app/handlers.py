#!/usr/bin/env python
# -*- coding: utf-8 -*-

from app import app, jwt, db, api, redis_store
# from flask import jsonify
# from .models import User, Container
# from .decorators import import_user
# from pylxd import Client
# from lgw import lxd_api_get


@jwt.user_identity_loader
def user_identity_lookup(user):
    """
    Return unique user identity
    :param user:
    :return: user.id:
    """
    return user.id


@jwt.user_claims_loader
def add_claims_to_access_token(user):
    """
    This claims is needed for custom verificatin between otp_access_token and regular access_token
    :param user:
    :return: jwt update
    """

    return {'otp_confirmed': user.otp_confirmed}


@jwt.token_in_blacklist_loader
def check_if_token_is_revoked(decrypted_token):
    """
    Create our function to check if a token has been blacklisted. In this simple
    case, we will just store the tokens jti (unique identifier) in redis
    whenever we create a new token (with the revoked status being 'false'). This
    function will return the revoked status of a token. If a token doesn't
    exist in this store, we don't know where it came from (as we are adding newly
    created tokens to our store with a revoked status of 'false'). In this case
    we will consider the token to be revoked, for safety purposes.
    """
    jti = decrypted_token['jti']
    entry = redis_store.get('access_jti:' + jti)
    entry_refresh = redis_store.get('refresh_jti:' + jti)
    # print(str(entry) + ' ' + str(jti))
    if entry is None and entry_refresh is None:
        return True
    #if entry_refresh is None:
    #    return True
    return entry == 'true'


'''
@app.before_request
def populate_containers_table():
    #print("populate_container_table")

    all = []
    res = lxd_api_get('containers')
    for c in res.json()['metadata']:
        all.append(c[16:])  # get container name from api url

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
'''
