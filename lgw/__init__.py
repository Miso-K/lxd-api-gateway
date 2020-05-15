#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import requests
import configparser
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
import json
import urllib3
from app import redis_store
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def scheduler_redis_job():
    print('Redis_job: updating data')
    all = []
    try:
        res = lxd_api_get('instances')
        for c in res.json()['metadata']:
            all.append(c[15:])  # get instance name from api url
    except Exception as e:
        print(e)

    if len(all) > 0:
        for c in all:
            res = lxd_api_get('instances/' + c)
            #print(res.json())
            redis_store.set('instances:' + c + ':info', json.dumps(res.json()['metadata']))

            res_state = lxd_api_get('instances/' + c + '/state')
            redis_store.set('instances:' + c + ':state', json.dumps(res_state.json()['metadata']))


def get_config():
    """
    Get configuration for LXD from lxdconfig.conf file
    :return: config object
    """

    config = configparser.ConfigParser()
    endpoint = ""
    try:
        config.read('lxdconfig.conf')
        endpoint = config['remote']['endpoint']
        cert = (config['remote']['cert_crt'], config['remote']['cert_key'])
        verify = True
        if config['remote']['verify'] == "False":
            verify = False
    except Exception as e:
        # print("Wrong config.conf file.")
        print("")
    return {'endpoint': endpoint, 'cert': cert, 'verify': verify}


def cts_stats(instances, redis_store):
    """
    Generate stats for user's all instances
    :param instances:
    :return: instances stats
    """

    count = len(instances)
    count_running = 0
    cpus_count = 0
    cpus_usage = 0
    processes_count = 0
    memory_count = 0
    memory_count_bytes = 0
    memory_current_count = 0
    disk_count = 0
    disk_count_bytes = 0
    disk_usage_count = 0
    price_count = 0

    for ct in instances:
        # ec = lxd_api_get('instances/'+ct).json()['metadata']
        # print('REDIS',ct,redis_store.get('cts:' + ct + ':info'))
        ec = json.loads(redis_store.get('instances:' + ct + ':info'))
        # sc =lxd_api_get('instances/' + ct + '/state').json()['metadata']

        if ec['status'] == "Running":
            count_running += 1

        '''cpus'''
        try:
            cpus = ec['expanded_config']['limits.cpu']
        except:
            cpus = None
        if cpus:
            cpus_count += int(cpus)
        # cpus_usage += int(sc['cpu']['usage'])
        # processes_count += int(sc['processes'])
        
        '''memory'''
        # memory_current_count += int(sc['memory']['usage'])
        try:
            memory = ec['expanded_config']['limits.memory']
        except:
            memory = None
        if memory:
            r = re.compile("([0-9]+)([a-zA-Z]+)")
            m = r.match(memory)
            b = convert_bytes(m.group(1), m.group(2))
            memory_count_bytes += b

        if memory_count_bytes:
            memory_count = memory_count_bytes / (1000 * 1000 * 1000)
            memory_count = '{0:.2f}'.format(memory_count)

        '''disk usage'''
        # try:
        #     disk_usage_count += int(cs['disk']['usage'])
        # except AttributeError:
        #     disk_usage_count = 0;

        '''disk size'''
        try:
            disk = ec['expanded_devices']['root']['size']
        except:
            disk = None

        if disk:
            r = re.compile("([0-9]+)([a-zA-Z]+)")
            m = r.match(disk)
            # print(m.group(1), m.group(2))
            b = convert_bytes(m.group(1), m.group(2))
            disk_count_bytes += + b
        if disk_count_bytes:
            disk_count = disk_count_bytes / (1000 * 1000 * 1000)
            disk_count = '{0:.2f}'.format(disk_count)

        '''price'''
        try:
            price = ec['expanded_config']['user.price']
        except:
            price = None
        if price:
            price_count += float(price)
    
    cts = {
        'type': 'stats',
        'instances': {
            'names': instances,
            'count': count,
            'count_running': count_running
        },
        'cpus': {
            'cpus_count': cpus_count,
            'cpus_usage': cpus_usage,
            'processes_count': processes_count
        },
        'memory': {
            'memory_count': memory_count,
            'memory_current_count': memory_current_count
        },
        'disk': {
            'disk_count': disk_count,
            'disk_usage': disk_usage_count
        },
        'price': {
            'price_count': price_count
        }
    }
    # print(cts)

    return cts    

   
def convert_bytes(size, type):
    """
    Returns B converted from KB/MB/GB
    :param size:
    :param type:
    :return:
    """

    bytes = 0
    if type == 'KB':
        bytes = int(size) * 1000
    if type == 'KiB':
        bytes = int(size) * 1024
    elif type == 'MB':
        bytes = int(size) * 1000 * 1000
    elif type == 'MiB':
        bytes = int(size) * 1024 * 1024
    elif type == 'GB':
        bytes = int(size) * 1000 * 1000 * 1000
    elif type == 'GiB':
        bytes = int(size) * 1024 * 1024 * 1024
    else: 
        bytes = size

    # print(bytes)
    return bytes


def send_request(subject, message, useremail=None):
    """
    Send mail to admin and reply to user if usermail set
    :param message:
    :param subject:
    :param useremail:
    :return: status message
    """

    config = configparser.ConfigParser()
    config.read('lxdconfig.conf')

    enabled = config['smtp']['enabled']
    if enabled == 'True':
        sender = config['smtp']['sender']
        to = config['smtp']['recipient']
        if config['smtp']['notify_user'] == 'True':
            cc = useremail
        else:
            cc = None

        # print("Sending email" + message + " subject: " + subject)

        content = MIMEText(message, 'html')

        try:
            if cc is not None:
                receivers = [cc] + [to]
            else:
                receivers = to
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = sender
            msg['To'] = to
            msg['Cc'] = cc
            msg["Date"] = formatdate(localtime=True)
            msg.attach(content)
            mailserver = smtplib.SMTP(config['smtp']['server'], config['smtp']['port'], timeout=30)
            mailserver.ehlo()
            mailserver.starttls()
            mailserver.ehlo()
            mailserver.login(config['smtp']['login'], config['smtp']['password'])
            try:
                # mailserver.sendmail(sender, receivers, msg.as_string())
                mailserver.send_message(msg, sender, receivers)
                print("Successfully sent email")
                return "Successfully sent email"
            except:
                return "Error: unable to send email"
            finally:
                mailserver.quit()
        except smtplib.SMTPException:
            print("Error: unable to send email")
            return "Error: unable to send email"


def send_otp_email(key, useremail=None):
    """
    Send mail to user with time based one time password
    :param key:
    :param useremail:
    :return: status message
    """

    config = configparser.ConfigParser()
    config.read('lxdconfig.conf')

    subject = 'Access key to ' + config['app']['production_name']
    message = 'Your otp access key is: ' + str(key)

    enabled = config['smtp']['enabled']
    if enabled == 'True':
        sender = config['smtp']['sender']
        to = useremail

        # print("Sending email" + " subject: " + subject + "message: " + message)

        content = MIMEText(message, 'html')

        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = sender
            msg['To'] = to
            msg["Date"] = formatdate(localtime=True)
            msg.attach(content)
            mailserver = smtplib.SMTP(config['smtp']['server'], config['smtp']['port'], timeout=30)
            mailserver.ehlo()
            mailserver.starttls()
            mailserver.ehlo()
            mailserver.login(config['smtp']['login'], config['smtp']['password'])
            try:
                # mailserver.sendmail(sender, receivers, msg.as_string())
                mailserver.send_message(msg, sender, to)
                # print("Successfully sent email")
                return "Successfully sent email"
            finally:
                mailserver.quit()
        except smtplib.SMTPException:
            # print("Error: unable to send email")
            return "Error: unable to send email"


def lxd_api_get(endpoint):
    """
    Get function for LXD API
    :param endpoint:
    :return: response:
    """

    r = requests.get(get_config()['endpoint'] + '/1.0/' + endpoint + '', verify=get_config()['verify'], cert=get_config()['cert'], timeout=100)
    #print(r.text)
    return r


def lxd_api_post(endpoint, data):
    """
    Post function for LXD API
    :param endpoint:
    :param data:
    :return: response:
    """

    r = requests.post(get_config()['endpoint'] + '/1.0/' + endpoint + '', verify=get_config()['verify'], cert=get_config()['cert'], data=json.dumps(data))
    #print(r.text)
    return r


def lxd_api_put(endpoint, data):
    """
    Put function for LXD API
    :param endpoint:
    :param data:
    :return: response:
    """

    r = requests.put(get_config()['endpoint'] + '/1.0/' + endpoint + '', verify=get_config()['verify'], cert=get_config()['cert'], data=json.dumps(data))
    #print(r.text)
    return r


def lxd_api_patch(endpoint, data):
    """
    Patch function for LXD API
    :param endpoint:
    :param data:
    :return: response:
    """

    r = requests.patch(get_config()['endpoint'] + '/1.0/' + endpoint + '', verify=get_config()['verify'], cert=get_config()['cert'], data=json.dumps(data))
    #print(r.text)
    return r


def lxd_api_delete(endpoint):
    """
    Delete function for LXD API
    :param endpoint:
    :return: response:
    """

    r = requests.delete(get_config()['endpoint'] + '/1.0/' + endpoint + '', verify=get_config()['verify'], cert=get_config()['cert'])
    #print(r.text)
    return r


def lxd_api_get_config():
    """
    Get function for get LXD API config
    :return: response:
    """

    r = requests.get(get_config()['endpoint'] + '/1.0', verify=get_config()['verify'], cert=get_config()['cert'])
    #print(r.text)
    return r

def lxd_remote_get():
    """
    Get function for get LXD API to remote
    :return: response:
    """

    r = requests.get('https://uk.images.linuxcontainers.org' + '/1.0/images/aliases?recursion=1', timeout=10)
    #print(r.text)
    return r
