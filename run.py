#!/usr/bin/env python
# -*- coding: utf-8 -*-
from app import app
import logging

try:
    host = app.config['HOST']
except KeyError:
    host = '127.0.0.1'

try:
    port = app.config['PORT']
except KeyError:
    port = 5000

try:
    ssl = app.config['SSL']
except KeyError:
    ssl = False


# Logging settings for development using werkzeug server
from flask.logging import default_handler
handler = default_handler
logging.getLogger('werkzeug').setLevel(logging.DEBUG)
logging.getLogger('werkzeug').addHandler(handler)
logging.getLogger('apscheduler.scheduler').setLevel(logging.INFO)
logging.getLogger('apscheduler.scheduler').addHandler(handler)
app.logger.setLevel(logging.DEBUG)
app.logger.addHandler(handler)

if ssl:
    app.run(host=host, port=port, threaded=True, ssl_context=(app.config['SSL_CERT'], app.config['SSL_KEY']), debug=False)
else:
    app.run(host=host, port=port, threaded=True, debug=False)

