#!/usr/bin/env python
# -*- coding: utf-8 -*-
import create_db
import populate_db

if __name__ == '__main__':
    print('Creating database...')
    try:
        create_db._run()
        print('Database created!')
    except Exception as e:
        raise e

    print('Populating database...')
    try:
        populate_db._run()
        print('Database populated!')
    except Exception as e:
        raise e
