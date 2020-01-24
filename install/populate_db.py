#!/usr/bin/env python
# -*- coding: utf-8 -*-
from app.models import *
import sys
import os
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))


def _run():
    ability = Ability(name='users_infos_all')  # 1 #admin
    db.session.add(ability)
    ability = Ability(name='users_create')  # 2 #admin
    db.session.add(ability)
    ability = Ability(name='users_infos')  # 3 #admin
    db.session.add(ability)
    ability = Ability(name='users_update')  # 4 #admin
    db.session.add(ability)
    ability = Ability(name='users_delete')  # 5 #admin
    db.session.add(ability)

    ability = Ability(name='groups_infos_all')  # 6 #admin
    db.session.add(ability)
    ability = Ability(name='groups_create')  # 7 #admin
    db.session.add(ability)
    ability = Ability(name='groups_infos')  # 8 #admin
    db.session.add(ability)
    ability = Ability(name='groups_update')  # 9 #admin
    db.session.add(ability)
    ability = Ability(name='groups_delete')  # 10 #admin
    db.session.add(ability)

    ability = Ability(name='abilities_infos_all')  # 11 #admin
    db.session.add(ability)
    ability = Ability(name='abilities_infos')  # 12 #admin
    db.session.add(ability)
    ability = Ability(name='abilities_update')  # 13 #admin
    db.session.add(ability)

    ability = Ability(name='me_infos')  # 14
    db.session.add(ability)
    ability = Ability(name='me_update')  # 15
    db.session.add(ability)
    ability = Ability(name='me_otp_create')  # 16
    db.session.add(ability)

    ability = Ability(name='requests_infos_all')  # 17
    db.session.add(ability)
    ability = Ability(name='requests_create')  # 18
    db.session.add(ability)
    ability = Ability(name='requests_infos')  # 19
    db.session.add(ability)
    ability = Ability(name='requests_update')  # 20
    db.session.add(ability)
    ability = Ability(name='requests_delete')  # 21 #admin
    db.session.add(ability)

    ability = Ability(name='containers_infos_all')  # 22
    db.session.add(ability)
    ability = Ability(name='containers_create')  # 23 #admin/user
    db.session.add(ability)
    ability = Ability(name='containers_infos')  # 24
    db.session.add(ability)
    ability = Ability(name='containers_update')  # 25 #admin/user
    db.session.add(ability)
    ability = Ability(name='containers_delete')  # 26 #admin/user
    db.session.add(ability)
    ability = Ability(name='containers_console')  # 27
    db.session.add(ability)
    ability = Ability(name='containers_state_infos')  # 28
    db.session.add(ability)
    ability = Ability(name='containers_state_update')  # 29
    db.session.add(ability)
    ability = Ability(name='containers_start')  # 30
    db.session.add(ability)
    ability = Ability(name='containers_freeze')  # 31
    db.session.add(ability)
    ability = Ability(name='containers_unfreeze')  # 32
    db.session.add(ability)
    ability = Ability(name='containers_stop')  # 33
    db.session.add(ability)
    ability = Ability(name='containers_stop_force')  # 34
    db.session.add(ability)
    ability = Ability(name='containers_restart')  # 35
    db.session.add(ability)

    ability = Ability(name='snapshots_infos_all')  # 36
    db.session.add(ability)
    ability = Ability(name='snapshots_create')  # 37
    db.session.add(ability)
    ability = Ability(name='snapshots_infos')  # 38
    db.session.add(ability)
    ability = Ability(name='snapshots_rename')  # 39
    db.session.add(ability)
    ability = Ability(name='snapshots_delete')  # 40
    db.session.add(ability)
    ability = Ability(name='snapshots_restore')  # 41 #admin/user
    db.session.add(ability)

    ability = Ability(name='images_infos_all')  # 42
    db.session.add(ability)
    ability = Ability(name='images_create')  # 43 #admin
    db.session.add(ability)
    ability = Ability(name='images_infos')  # 44
    db.session.add(ability)
    ability = Ability(name='images_update')  # 45 #admin
    db.session.add(ability)
    ability = Ability(name='images_delete')  # 46 #admin
    db.session.add(ability)
    ability = Ability(name='images_aliases_infos_all')  # 47
    db.session.add(ability)
    ability = Ability(name='images_aliases_create')  # 48 #admin
    db.session.add(ability)
    ability = Ability(name='images_aliases_infos')  # 49
    db.session.add(ability)
    ability = Ability(name='images_aliases_update')  # 50 #admin
    db.session.add(ability)
    ability = Ability(name='images_aliases_delete')  # 51 #admin
    db.session.add(ability)
    ability = Ability(name='images_remote_infos_all')  # 52 #admin
    db.session.add(ability)

    ability = Ability(name='operations_infos')  # 53
    db.session.add(ability)
    ability = Ability(name='lxd_infos')  # 54 #admin
    db.session.add(ability)
    ability = Ability(name='resources_infos')  # 55 #admin
    db.session.add(ability)
    ability = Ability(name='stats_infos')  # 56
    db.session.add(ability)
    ability = Ability(name='config_infos')  # 57
    db.session.add(ability)
    ability = Ability(name='config_update')  # 58 #admin
    db.session.add(ability)
    ability = Ability(name='lxd_certs_create')  # 59 #admin
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
                   31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 42, 44, 47,
                   49, 53, 56, 57]
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
