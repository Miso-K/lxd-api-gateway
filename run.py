#!/usr/bin/env python
# -*- coding: utf-8 -*-
from app import app
from lgw import scheduler_redis_job

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



from apscheduler.schedulers.background import BackgroundScheduler

# The "apscheduler." prefix is hard coded
scheduler = BackgroundScheduler(daemon=True)
scheduler.add_job(scheduler_redis_job, 'interval', minutes=5)

scheduler.start()

if ssl:
	app.run(host=host, port=port, threaded=True, ssl_context=(app.config['SSL_CERT'], app.config['SSL_KEY']), debug=True)
else:
	app.run(host=host, port=port, threaded=True, debug=True)
