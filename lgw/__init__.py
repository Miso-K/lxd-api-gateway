#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
import configparser
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
import json
import urllib3
from app import redis_store, logger
import logging
from OpenSSL import crypto
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def scheduler_redis_job():
    #print('Redis_job: updating data in redis DB')
    logger.info('Redis_job: updating data in redis DB')

    database_lxdservers_list = redis_store.keys('servers:*')
    #print(database_lxdservers_list)

    for serverkey in database_lxdservers_list:
        lxdserver = json.loads(redis_store.get(serverkey))
        all = []
        try:
            res = lxd_api_get_scheduler(lxdserver, 'instances')
            for c in res.json()['metadata']:
                all.append(c[15:])  # get instance name from api url
        except Exception as e:
            print(e)
        #print(all)
        if len(all) > 0:
            for c in all:
                res = lxd_api_get_scheduler(lxdserver, 'instances/' + c)
                redis_store.set('server:' + lxdserver['name'] + ':instance:' + c + ':info', json.dumps(res.json()['metadata']))
                # print(res.json()['metadata'])

                res_state = lxd_api_get_scheduler(lxdserver, 'instances/' + c + '/state')
                redis_store.set('server:' + lxdserver['name'] + ':instance:' + c + ':state', json.dumps(res_state.json()['metadata']))


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


def lxd_api_get_scheduler(server, endpoint):
    """
    Get function for LXD API
    :param endpoint:
    :return: response:
    """
    cert = ('certs/' + server['key_public'], 'certs/' + server['key_private'])
    r = requests.get(server['address'] + '/1.0/' + endpoint + '', verify=get_config()['verify'], cert=cert, timeout=100)
    #print(r.text)
    return r


def lxd_api_get(server, endpoint):
    """
    Get function for LXD API
    :param endpoint:
    :return: response:
    """
    cert = ('certs/' + server.key_public, 'certs/' + server.key_private)
    r = requests.get(server.address + '/1.0/' + endpoint + '', verify=get_config()['verify'], cert=cert, timeout=100)
    #print(r.text)
    return r


def lxd_api_post(server, endpoint, data):
    """
    Post function for LXD API
    :param endpoint:
    :param data:
    :return: response:
    """
    cert = ('certs/' + server.key_public, 'certs/' + server.key_private)
    r = requests.post(server.address + '/1.0/' + endpoint + '', verify=get_config()['verify'], cert=cert, data=json.dumps(data))

    #r = requests.post(get_config()['endpoint'] + '/1.0/' + endpoint + '', verify=get_config()['verify'], cert=get_config()['cert'], data=json.dumps(data))
    #print(r.text)
    return r


def lxd_api_put(server, endpoint, data):
    """
    Put function for LXD API
    :param endpoint:
    :param data:
    :return: response:
    """
    cert = ('certs/' + server.key_public, 'certs/' + server.key_private)
    r = requests.put(server.address + '/1.0/' + endpoint + '', verify=get_config()['verify'], cert=cert,
                     data=json.dumps(data))

    #r = requests.put(get_config()['endpoint'] + '/1.0/' + endpoint + '', verify=get_config()['verify'], cert=get_config()['cert'], data=json.dumps(data))
    #print(r.text)
    return r


def lxd_api_patch(server, endpoint, data):
    """
    Patch function for LXD API
    :param endpoint:
    :param data:
    :return: response:
    """
    cert = ('certs/' + server.key_public, 'certs/' + server.key_private)
    r = requests.patch(server.address + '/1.0/' + endpoint + '', verify=get_config()['verify'], cert=cert,
                     data=json.dumps(data))

    r = requests.patch(get_config()['endpoint'] + '/1.0/' + endpoint + '', verify=get_config()['verify'], cert=get_config()['cert'], data=json.dumps(data))
    #print(r.text)
    return r


def lxd_api_delete(server, endpoint):
    """
    Delete function for LXD API
    :param endpoint:
    :return: response:
    """
    cert = ('certs/' + server.key_public, 'certs/' + server.key_private)
    r = requests.delete(server.address + '/1.0/' + endpoint + '', verify=get_config()['verify'], cert=cert)

    #r = requests.delete(get_config()['endpoint'] + '/1.0/' + endpoint + '', verify=get_config()['verify'], cert=get_config()['cert'])
    #print(r.text)
    return r


def lxd_api_get_config(server):
    """
    Get function for get LXD API config
    :return: response:
    """
    cert = ('certs/' + server.key_public, 'certs/' + server.key_private)
    r = requests.get(server.address + '/1.0', verify=get_config()['verify'], cert=cert)

    #r = requests.get(get_config()['endpoint'] + '/1.0', verify=get_config()['verify'], cert=get_config()['cert'])
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


def certificate_generator(
    emailAddress="lxdmanager",
    commonName="lxdmanager",
    countryName="SK",
    localityName="Slovakia",
    stateOrProvinceName="Slovakia",
    organizationName="lxdmanger",
    organizationUnitName="lxdmanager",
    serialNumber=0,
    validityStartInSeconds=0,
    validityEndInSeconds=10*365*24*60*60,
    KEY_FILE="test_key.key",
    CERT_FILE="test_key.crt"):

    #can look at generated file using openssl:
    #openssl x509 -inform pem -in selfsigned.crt -noout -text
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = countryName
    cert.get_subject().ST = stateOrProvinceName
    cert.get_subject().L = localityName
    cert.get_subject().O = organizationName
    cert.get_subject().OU = organizationUnitName
    cert.get_subject().CN = commonName
    cert.get_subject().emailAddress = emailAddress
    cert.set_serial_number(serialNumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    with open(CERT_FILE, "w") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(KEY_FILE, "w") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))


def send_cert_to_server(server_name='lxd', server_address='https:127.0.0.1:8443', server_password=''):

    key_file = 'certs/' + server_name + '_key.key'
    cert_file = 'certs/' + server_name + '_key.crt'
    certificate_generator(KEY_FILE=key_file, CERT_FILE=cert_file)

    with open(cert_file, 'r') as f:
        cert = ''.join(f.readlines()[1:-1])
        f.close()

    data = {
        "type": "client",
        "certificate": cert,
        "name": server_name,
        "password": server_password
    }
    #print(data)
    data = json.dumps(data)
    r = requests.post(server_address + '/1.0/' + 'certificates' + '', data=data, verify=False)
    print(r.text)
    return r


