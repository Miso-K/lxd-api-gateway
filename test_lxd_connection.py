# If not working, try this curl
# curl -s -k --cert ./lxd-vpsadmin.crt --key ./lxd-vpsadmin.key https://127.0.0.1:8443/1.0 -vvv

import requests
import configparser


def get_config():
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


def lxd_api_get(endpoint):
    r = requests.get(get_config()['endpoint'] + '/1.0' + endpoint + '', verify=get_config()['verify'], cert=get_config()['cert'], timeout=10)
    #print(r.text)
    return r


def lxd_api_delete(endpoint):
    r = requests.delete(get_config()['endpoint'] + '/1.0/' + endpoint + '', verify=get_config()['verify'], cert=get_config()['cert'])
    #print(r.text)
    return r


def main():
    print(lxd_api_get(''))
    print(lxd_api_get('/containers').text)
    print(lxd_api_delete('containers/aaaae').text)


if __name__ == "__main__":
    main()
