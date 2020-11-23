#!/usr/bin/env python
# -*- coding: utf-8 -*-
from app.models import *
import sys
import os
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))


def _run():
    ability = Ability(name='users_infos_all', category='users')  # 1 #admin
    db.session.add(ability)
    ability = Ability(name='users_create', category='users')  # 2 #admin
    db.session.add(ability)
    ability = Ability(name='users_infos', category='users')  # 3 #admin
    db.session.add(ability)
    ability = Ability(name='users_update', category='users')  # 4 #admin
    db.session.add(ability)
    ability = Ability(name='users_delete', category='users')  # 5 #admin
    db.session.add(ability)

    ability = Ability(name='groups_infos_all', category='groups')  # 6
    db.session.add(ability)
    ability = Ability(name='groups_create', category='groups')  # 7 #admin
    db.session.add(ability)
    ability = Ability(name='groups_infos', category='groups')  # 8 #admin
    db.session.add(ability)
    ability = Ability(name='groups_update', category='groups')  # 9 #admin
    db.session.add(ability)
    ability = Ability(name='groups_delete', category='groups')  # 10 #admin
    db.session.add(ability)

    ability = Ability(name='abilities_infos_all', category='abilities')  # 11
    db.session.add(ability)
    ability = Ability(name='abilities_infos', category='abilities')  # 12 #admin
    db.session.add(ability)
    ability = Ability(name='abilities_update', category='abilities')  # 13 #admin
    db.session.add(ability)

    ability = Ability(name='me_infos', category='me')  # 14
    db.session.add(ability)
    ability = Ability(name='me_update', category='me')  # 15
    db.session.add(ability)
    ability = Ability(name='me_otp_create', category='me')  # 16
    db.session.add(ability)

    ability = Ability(name='requests_infos_all', category='requests')  # 17
    db.session.add(ability)
    ability = Ability(name='requests_create', category='requests')  # 18
    db.session.add(ability)
    ability = Ability(name='requests_infos', category='requests')  # 19
    db.session.add(ability)
    ability = Ability(name='requests_update', category='requests')  # 20
    db.session.add(ability)
    ability = Ability(name='requests_delete', category='requests')  # 21 #admin
    db.session.add(ability)

    ability = Ability(name='instances_infos_all', category='instances')  # 22
    db.session.add(ability)
    ability = Ability(name='instances_create', category='instances')  # 23 #admin/user
    db.session.add(ability)
    ability = Ability(name='instances_infos', category='instances')  # 24
    db.session.add(ability)
    ability = Ability(name='instances_update', category='instances')  # 25 #admin/user
    db.session.add(ability)
    ability = Ability(name='instances_delete', category='instances')  # 26 #admin/user
    db.session.add(ability)
    ability = Ability(name='instances_console', category='instances')  # 27
    db.session.add(ability)
    ability = Ability(name='instances_state_infos', category='instances')  # 28
    db.session.add(ability)
    ability = Ability(name='instances_state_update', category='instances')  # 29
    db.session.add(ability)

    ability = Ability(name='snapshots_infos_all', category='snapshots')  # 30
    db.session.add(ability)
    ability = Ability(name='snapshots_create', category='snapshots')  # 31
    db.session.add(ability)
    ability = Ability(name='snapshots_infos', category='snapshots')  # 32
    db.session.add(ability)
    ability = Ability(name='snapshots_rename', category='snapshots')  # 33
    db.session.add(ability)
    ability = Ability(name='snapshots_delete', category='snapshots')  # 34
    db.session.add(ability)
    ability = Ability(name='snapshots_restore', category='snapshots')  # 35 #admin/user
    db.session.add(ability)

    ability = Ability(name='images_infos_all', category='images')  # 36
    db.session.add(ability)
    ability = Ability(name='images_create', category='images')  # 37 #admin
    db.session.add(ability)
    ability = Ability(name='images_infos', category='images')  # 38
    db.session.add(ability)
    ability = Ability(name='images_update', category='images')  # 39 #admin
    db.session.add(ability)
    ability = Ability(name='images_delete', category='images')  # 40 #admin
    db.session.add(ability)
    ability = Ability(name='images_aliases_infos_all', category='images')  # 41
    db.session.add(ability)
    ability = Ability(name='images_aliases_create', category='images')  # 42 #admin
    db.session.add(ability)
    ability = Ability(name='images_aliases_infos', category='images')  # 43
    db.session.add(ability)
    ability = Ability(name='images_aliases_update', category='images')  # 44 #admin
    db.session.add(ability)
    ability = Ability(name='images_aliases_delete', category='images')  # 45 #admin
    db.session.add(ability)
    ability = Ability(name='images_remote_infos_all', category='images')  # 46 #admin
    db.session.add(ability)

    ability = Ability(name='universals_infos_all', category='universals')  # 47 #admin
    db.session.add(ability)
    ability = Ability(name='universals_create', category='universals')  # 48 #admin
    db.session.add(ability)
    ability = Ability(name='universals_infos', category='universals')  # 49 #admin
    db.session.add(ability)
    ability = Ability(name='universals_update', category='universals')  # 50 #admin
    db.session.add(ability)
    ability = Ability(name='universals_rename', category='universals')  # 51 #admin
    db.session.add(ability)
    ability = Ability(name='universals_delete', category='universals')  # 52 #admin
    db.session.add(ability)

    ability = Ability(name='servers_infos_all', category='servers')  # 53 #admin
    db.session.add(ability)
    ability = Ability(name='servers_create', category='servers')  # 54 #admin
    db.session.add(ability)
    ability = Ability(name='servers_infos', category='servers')  # 55 #admin
    db.session.add(ability)
    ability = Ability(name='servers_delete', category='servers')  # 56 #admin
    db.session.add(ability)

    ability = Ability(name='config_infos', category='configs')  # 57
    db.session.add(ability)
    ability = Ability(name='config_update', category='configs')  # 58 #admin
    db.session.add(ability)

    ability = Ability(name='operations_infos', category='other')  # 59
    db.session.add(ability)
    ability = Ability(name='lxd_server_infos', category='other')  # 60 #admin
    db.session.add(ability)



    db.session.commit()

    group= Group(
        name='admin',
        abilities=[i for i in range(1, 59)]
    )

    db.session.add(group)
    db.session.commit()

    group2 = Group(
        name='user',
        abilities=[6, 11, 14, 15, 16, 17, 18, 19, 20, 22, 24, 27, 28, 29, 30,
                   31, 32, 33, 34, 35, 36, 38, 39, 41, 43, 57, 59]
    )

    db.session.add(group2)
    db.session.commit()

    user = User(
        admin=True,
        name='John Doe',
        username='admin',
        groups=[1]
    )

    passwd = os.getenv('ADMIN_PASSWORD')
    if passwd:
        user.hash_password(passwd)
    else:
        user.hash_password('admin1234')
    db.session.add(user)
    db.session.commit()


if __name__ == '__main__':
    _run()
