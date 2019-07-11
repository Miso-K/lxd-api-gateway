#!/usr/bin/env python
# -*- coding: utf-8 -*-
from app.models import *
import sys
import os
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))


def _run():
    ability = Ability(name='users_infos_all')  # 1
    db.session.add(ability)
    ability = Ability(name='users_create')  # 2
    db.session.add(ability)
    ability = Ability(name='users_infos')  # 3
    db.session.add(ability)
    ability = Ability(name='users_update')  # 4
    db.session.add(ability)
    ability = Ability(name='users_delete')  # 5
    db.session.add(ability)
    ability = Ability(name='groups_infos_all')  # 6
    db.session.add(ability)
    ability = Ability(name='groups_create')  # 7
    db.session.add(ability)
    ability = Ability(name='groups_infos')  # 8
    db.session.add(ability)
    ability = Ability(name='groups_update')  # 9
    db.session.add(ability)
    ability = Ability(name='groups_delete')  # 10
    db.session.add(ability)
    ability = Ability(name='abilities_infos_all')  # 11
    db.session.add(ability)
    ability = Ability(name='abilities_infos')  # 12
    db.session.add(ability)
    ability = Ability(name='abilities_update')  # 13
    db.session.add(ability)
    ability = Ability(name='ct_infos')  # 14
    db.session.add(ability)
    ability = Ability(name='ct_create')  # 15
    db.session.add(ability)
    ability = Ability(name='ct_clone')  # 16
    db.session.add(ability)
    ability = Ability(name='ct_update')  # 17
    db.session.add(ability)
    ability = Ability(name='ct_delete')  # 18
    db.session.add(ability)
    ability = Ability(name='ct_start')  # 19
    db.session.add(ability)
    ability = Ability(name='ct_freeze')  # 20
    db.session.add(ability)
    ability = Ability(name='ct_unfreeze')  # 21
    db.session.add(ability)
    ability = Ability(name='ct_stop')  # 22
    db.session.add(ability)
    ability = Ability(name='ct_restart')  # 23
    db.session.add(ability)
    ability = Ability(name='lxc_infos')  # 24
    db.session.add(ability)
    ability = Ability(name='cts_stats')  # 25
    db.session.add(ability)
    ability = Ability(name='me_edit')  # 26
    db.session.add(ability)
    ability = Ability(name='me_otp')  # 27
    db.session.add(ability)
    ability = Ability(name='ct_terminal')  # 28
    db.session.add(ability)
    ability = Ability(name='snapshot_infos')  # 29
    db.session.add(ability)
    ability = Ability(name='snapshot_create')  # 30
    db.session.add(ability)
    ability = Ability(name='snapshot_rename')  # 31
    db.session.add(ability)
    ability = Ability(name='snapshot_delete')  # 32
    db.session.add(ability)
    ability = Ability(name='snapshot_restore')  # 33
    db.session.add(ability)
    ability = Ability(name='users_request')  # 34
    db.session.add(ability)
    ability = Ability(name='lxd_config')  # 35
    db.session.add(ability)
    ability = Ability(name='lxd_certs')  # 36
    db.session.add(ability)

    db.session.commit()

    group= Group(
        name='admin',
        abilities=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36]
    )

    db.session.add(group)
    db.session.commit()

    group2 = Group(
        name='user',
        abilities=[6, 8, 14, 19, 20, 21, 22, 23, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34]
    )

    db.session.add(group2)
    db.session.commit()

    user = User(
        admin=True,
        name='John Doe',
        username='admin',
        groups=[1]
    )

    user.hash_password('admin1234')

    db.session.add(user)
    db.session.commit()


if __name__ == '__main__':
    _run()
