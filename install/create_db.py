#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os.path
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))

from app.models import *


def _run():
    db.reflect()
    db.drop_all()
    db.create_all()
    db.session.commit()

if __name__ == '__main__':
    _run()
