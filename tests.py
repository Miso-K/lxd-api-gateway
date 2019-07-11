#!/usr/bin/env python -W ignore
# -*- coding: utf-8 -*-
import sys
sys.path.append('../')
import os

from app import app, db
from install import populate_db

import unittest
import tempfile
import json
import time
import warnings


def ignore_warnings(test_func):
    def do_test(self, *args, **kwargs):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            test_func(self, *args, **kwargs)
    return do_test


class AppTestCase(unittest.TestCase):
    token = None

    @ignore_warnings
    def setUp(self):
        self.db_fd, app.config['DATABASE'] = tempfile.mkstemp()
        app.config[
            'SQLALCHEMY_DATABASE_URI'] = 'sqlite:///%s \
            ' % app.config['DATABASE']
        app.testing = True
        self.app = app.test_client()
        with app.app_context():
            db.create_all()
            populate_db._run()

    @ignore_warnings
    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(app.config['DATABASE'])

    @ignore_warnings
    def test_001_get_auth(self):
        rv = self.app.post('/api/v1/auth', data=json.dumps({
            'username': 'admin',
            'password': 'monopol256'
        }), content_type='application/json')
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertIn('access_token', rj)
        self.__class__.token = rj['access_token']

    @ignore_warnings
    def test_002_get_auth_refresh(self):
        rv = self.app.post(
            '/api/v1/auth/refresh', headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertIn('access_token', rj)

    @ignore_warnings
    def test_003_get_auth_check(self):
        rv = self.app.get(
            '/api/v1/auth/check', headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rj, {})

    @ignore_warnings
    def test_004_get_auth_check_wrong_token(self):
        rv = self.app.get(
            '/api/v1/auth/check', headers={
                'Authorization': 'Bearer ODAZHIJDIOAZN'
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 422)

    @ignore_warnings
    def test_005_get_lwp_users(self):
        rv = self.app.get(
            '/api/v1/lwp/users', headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(len(rj['data']), 1)
        self.assertEqual(rj['data'][0]['id'], 1)
        self.assertEqual(rj['data'][0]['type'], 'users')

    @ignore_warnings
    def test_006_get_lwp_users_1(self):
        rv = self.app.get(
            '/api/v1/lwp/users/1', headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rj['data']['id'], 1)
        self.assertTrue(rj['data']['attributes']['admin'])
        self.assertEqual(rj['data']['attributes']['username'], 'admin')
        self.assertEqual(rj['data']['attributes']['name'], 'John Doe')
        self.assertIsNone(rj['data']['attributes']['email'])
        self.assertEqual(rj['data']['type'], 'users')

    @ignore_warnings
    def test_007_put_lwp_users_1(self):
        rv = self.app.put(
            '/api/v1/lwp/users/1',
            data=json.dumps({
                "data": {
                    "relationships": {
                        "groups": {
                            "data": []
                        }
                    },
                    "attributes": {
                        "admin": False,
                        "email": "elie@deloumeau.fr",
                        "name": "Élie Deloumeau",
                        "password": "elie",
                    },
                    "type": "users"
                }
            }),
            content_type='application/json',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rj['data']['id'], 1)
        self.assertFalse(rj['data']['attributes']['admin'])
        self.assertEqual(rj['data']['attributes']['username'], 'admin')
        self.assertEqual(rj['data']['attributes']['name'], 'Élie Deloumeau')
        self.assertEqual(rj['data']['attributes'][
                         'email'], 'elie@deloumeau.fr')
        self.assertEqual(rj['data']['type'], 'users')

    ''''@ignore_warnings
    def test_107_delete_lwp_users_1(self):
        rv = self.app.delete(
            '/api/v1/lwp/users/1',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        print(rv.get_data(as_text=True))
        rj = json.loads(rv.get_data(as_text=True))

        # Assert token error : Not enough segments
        self.assertEqual(rv.status_code, 422)
        self.assertEqual(rj['msg'], 'Not enough segments')
    '''

    @ignore_warnings
    def test_008_post_lwp_users(self):
        rv = self.app.post(
            '/api/v1/lwp/users',
            data=json.dumps({
                "data": {
                    "relationships": {
                        "groups": {
                            "data": [
                                {
                                    "id": 1,
                                    "type": "groups"
                                }
                            ]
                        }
                    },
                    "attributes": {
                        "admin": False,
                        "email": "test@test.test",
                        "name": "test",
                        "password": "test",
                        "username": "test"
                    },
                    "type": "users"
                }
            }),
            content_type='application/json',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 201)
        self.assertEqual(rj['data']['id'], 2)
        self.assertFalse(rj['data']['attributes']['admin'])
        self.assertEqual(rj['data']['attributes']['username'], 'test')
        self.assertEqual(rj['data']['attributes']['name'], 'test')
        self.assertEqual(rj['data']['attributes']['email'], 'test@test.test')
        self.assertEqual(rj['data']['type'], 'users')

    @ignore_warnings
    def test_009_get_lwp_me(self):
        rv = self.app.get(
            '/api/v1/lwp/me', headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rj['data']['id'], 1)
        self.assertTrue(rj['data']['attributes']['admin'])
        self.assertEqual(rj['data']['attributes']['username'], 'admin')
        self.assertEqual(rj['data']['attributes']['name'], 'John Doe')
        self.assertIsNone(rj['data']['attributes']['email'])
        self.assertEqual(rj['data']['type'], 'users')

    @ignore_warnings
    def test_010_put_lwp_me(self):
        rv = self.app.put(
            '/api/v1/lwp/me',
            data=json.dumps({
                "data": {
                    "attributes": {
                        "admin": True,
                        "email": "elie@deloumeau.fr",
                        "name": "Élie Deloumeau",
                        "password": "elie",
                    },
                    "type": "users"
                }
            }),
            content_type='application/json',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rj['data']['id'], 1)
        self.assertTrue(rj['data']['attributes']['admin'])
        self.assertEqual(rj['data']['attributes']['username'], 'admin')
        self.assertEqual(rj['data']['attributes']['name'], 'Élie Deloumeau')
        self.assertEqual(rj['data']['attributes'][
                         'email'], 'elie@deloumeau.fr')
        self.assertEqual(rj['data']['type'], 'users')

    # def test_802_delete_me(self):
    #     rv = self.app.delete(
    #         '/api/v1/lwp/me',
    #         headers={
    #             'Authorization': 'Bearer %s' % self.__class__.token
    #         })
    #     rj = json.loads(rv.get_data(as_text=True))

    #     self.assertEqual(rv.status_code, 422)
    #     self.assertEqual(rj['msg'], 'Not enough segments')

    @ignore_warnings
    def test_011_get_lwp_groups(self):
        rv = self.app.get(
            '/api/v1/lwp/groups', headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(len(rj['data']), 2)
        self.assertEqual(rj['data'][0]['id'], 1)
        self.assertEqual(rj['data'][0]['type'], 'groups')

    @ignore_warnings
    def test_012_get_lwp_groups_1(self):
        rv = self.app.get(
            '/api/v1/lwp/groups/1', headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rj['data']['id'], 1)
        self.assertEqual(rj['data']['attributes']['name'], 'admin')
        self.assertEqual(rj['data']['type'], 'groups')

    @ignore_warnings
    def test_013_put_lwp_groups_1(self):
        rv = self.app.put(
            '/api/v1/lwp/groups/1',
            data=json.dumps({
                "data": {
                    "relationships": {
                        "abilities": {
                            "data": [
                                {
                                    "id": 1,
                                    "type": "abilities"
                                },
                                {
                                    "id": 5,
                                    "type": "abilities"
                                }
                            ]
                        },
                        "users": {
                            "data": [
                                {
                                    "id": 1,
                                    "type": "users"
                                }
                            ]
                        }
                    },
                    "attributes": {
                        "name": "admin-test",
                    },
                    "type": "groups"
                }
            }),
            content_type='application/json',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rj['data']['id'], 1)
        self.assertEqual(rj['data']['attributes']['name'], 'admin-test')
        self.assertEqual(rj['data']['type'], 'groups')

    # def test_802_delete_lwp_groups_1(self):
    #     rv = self.app.delete(
    #         '/api/v1/lwp/groups/1',
    #         headers={
    #             'Authorization': 'Bearer %s' % self.__class__.token
    #         })
    #     print(rv.get_data(as_text=True))
    #     rj = json.loads(rv.get_data(as_text=True))

    #     self.assertEqual(rv.status_code, 422)
    #     self.assertEqual(rj['msg'], 'Not enough segments')

    @ignore_warnings
    def test_014_post_lwp_groups(self):
        rv = self.app.post(
            '/api/v1/lwp/groups',
            data=json.dumps({
                "data": {
                    "relationships": {
                        "abilities": {
                            "data": [
                                {
                                    "id": 1,
                                    "type": "abilities"
                                },
                                {
                                    "id": 5,
                                    "type": "abilities"
                                }
                            ]
                        },
                        "users": {
                            "data": [
                                {
                                    "id": 1,
                                    "type": "users"
                                }
                            ]
                        }
                    },
                    "attributes": {
                        "name": "test"
                    },
                    "type": "groups"
                }
            }),
            content_type='application/json',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 201)
        self.assertEqual(rj['data']['id'], 3)
        self.assertEqual(rj['data']['attributes']['name'], 'test')
        self.assertEqual(rj['data']['type'], 'groups')

    @ignore_warnings
    def test_015_get_lwp_abilities(self):
        rv = self.app.get(
            '/api/v1/lwp/abilities', headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(len(rj['data']), 26)
        self.assertEqual(rj['data'][0]['id'], 1)
        self.assertEqual(rj['data'][0]['type'], 'abilities')

    @ignore_warnings
    def test_016_get_lwp_abilities_1(self):
        rv = self.app.get(
            '/api/v1/lwp/abilities/1', headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rj['data']['id'], 1)
        self.assertEqual(rj['data']['attributes']['name'], 'users_infos_all')
        self.assertEqual(rj['data']['type'], 'abilities')

    @ignore_warnings
    def test_017_put_lwp_abilities_1(self):
        rv = self.app.put(
            '/api/v1/lwp/abilities/1',
            data=json.dumps({
                "data": {
                    "relationships": {
                        "groups": {
                            "data": [
                                {
                                    "id": 1,
                                    "type": "groups"
                                }
                            ]
                        }
                    },
                    "type": "abilities"
                }
            }),
            content_type='application/json',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rj['data']['id'], 1)
        self.assertEqual(rj['data']['attributes']['name'], 'users_infos_all')
        self.assertEqual(rj['data']['type'], 'abilities')

    @ignore_warnings
    def test_018_get_lxc_containers(self):
        rv = self.app.get(
            '/api/v1/lxc/containers', headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(len(rj['data']), 0)


    @ignore_warnings
    def test_202_post_lxc_containers(self):
        rv = self.app.post(
            '/api/v1/lxc/containers',
            data=json.dumps({
                "data": {
                    "relationships": {
                        "users": {
                            "data": [
                                {
                                    "id": 0,
                                    "type": "users"
                                }
                            ]
                        }
                    },
                    "attributes": {
                        "source": {
                            "type": "image",
                            "alias": "ubuntu/16.04"
                        },
                        "name": "test-vps1",
                        "config": {
                            "limits_memory": "256MB",
                            "limits_cpu": "1"
                        }
                    },
                    "type": "containers"
                }
}),
            content_type='application/json',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 201)
        #self.assertEqual(rj['data']['id'], 0) # null as id ?
        self.assertEqual(
            rj['data']['relationships']['users']['data'][0]['id'], 0
        )
        self.assertEqual(
            rj['data']['relationships']['users']['data'][0]['type'], 'users'
        )
        self.assertEqual(rj['data']['attributes']['name'], 'test-vps1')
        self.assertEqual(rj['data']['attributes']['config']['limits_memory'], '256MB')
        self.assertEqual(rj['data']['attributes']['config']['limits_cpu'], '1')
        self.assertEqual(rj['data']['type'], 'containers')

    # najskor asi post musi vratit ID noveho kontajnera
    '''
    @ignore_warnings
    def test_0191_get_lxc_containers(self):
        time.sleep(5)
        rv = self.app.get(
            '/api/v1/lxc/containers', headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))
        print(rj['data'])
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(len(rj['data']), 1)
    '''

    '''
    @ignore_warnings
    def test_019_post_lxc_containers_1_start(self):
        rv = self.app.post(
            '/api/v1/lxc/containers/1/start',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })

        self.assertEqual(rv.status_code, 204)
    
    @ignore_warnings
    def test_020_post_lxc_containers_1_freeze(self):
        rv = self.app.post(
            '/api/v1/lxc/containers/1/freeze',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })

        self.assertEqual(rv.status_code, 204)

    @ignore_warnings
    def test_021_post_lxc_containers_1_unfreeze(self):
        rv = self.app.post(
            '/api/v1/lxc/containers/1/unfreeze',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })

        self.assertEqual(rv.status_code, 204)

    @ignore_warnings
    def test_022_post_lxc_containers_1_stop(self):
        rv = self.app.post(
            '/api/v1/lxc/containers/1/stop',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })

        self.assertEqual(rv.status_code, 204)

    @ignore_warnings
    def test_023_post_lxc_containers_1_start(self):
        rv = self.app.post(
            '/api/v1/lxc/containers/1/start',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })

        self.assertEqual(rv.status_code, 204)

    @ignore_warnings
    def test_024_post_lxc_containers_1_restart(self):
        rv = self.app.post(
            '/api/v1/lxc/containers/1/restart',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        self.assertEqual(rv.status_code, 204)
    '''
    '''
    @ignore_warnings
    def test_225_put_lxc_containers(self):
        rv = self.app.put(
            '/api/v1/lxc/containers/1',
            data=json.dumps({
                "data": {
                    "relationships": {
                        "users": {
                            "data": [
                                {
                                "id": 0,
                                "type": "users"
                                }
                            ]
                        }
                    },
                    "attributes": {
                        "config": {
                            "limits_memory": "",
                            "limits_cpu": ""
                        },
                        "name": "test-vps2"
                    },
                    "type": "containers"
                }
            }),
            content_type='application/json',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 201)
        self.assertEqual(rj['data']['id'], 1)
        self.assertEqual(
            rj['data']['relationships']['users']['data'][0]['id'], 0
        )
        self.assertEqual(
            rj['data']['relationships']['users']['data'][0]['type'], 'users'
        )
        self.assertEqual(rj['data']['attributes']['name'], 'test-vps2')
        self.assertEqual(rj['data']['attributes']['config']['limits_memory'], '')
        self.assertEqual(rj['data']['attributes']['config']['limits_cpu'], '')
        self.assertEqual(rj['data']['type'], 'containers')
        '''

    ''' #nemam containers delete ?
    def test_208_delete_lxc_containers_1(self):
        rv = self.app.delete(
            '/api/v1/lxc/containers/1',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })

        self.assertEqual(rv.status_code, 204)
    '''

if __name__ == '__main__':
    unittest.main()
