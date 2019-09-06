lxd-api-gateway

RESTful API for LXD with USER access limitations

Use it with [Dashboard](https://github.com/Miso-K/lxd-api-gateway)

[![Python version](https://img.shields.io/badge/Python-3.7-blue.svg)](https://www.python.org/downloads/release/python-350/)

---

## Installation
### Clone
```shell
git clone --recursive https://github.com/Miso-K/lxd-api-gateway
```

### Install requirements
```shell
# install python dependencies
apt update
apt install python3-pip python3-dev build-essential libssl-dev libffi-dev python3-setuptools
apt install python3-venv

cd lxc-rest

# create virtual env
python3 -m venv lxd-rest-env

# activate env
source lgw-env/bin/activate

pip install -r requirements.txt
```

### Change secret key to unique
``` shell
nano config/default.py
```

### Update lxdconfig.conf
```
nano lxdconfig.conf
```

### Create database
```shell
python3 install/setup.py
```

---

### LXD host settings

Change "example.com" to your domain. * would make it accessible from everywhere.

```shell
sudo lxc config set core.https_address [::]:8443
sudo lxc config set core.https_allowed_origin "*.example.com"
sudo lxc config set core.https_allowed_methods "GET, POST, PUT, DELETE, OPTIONS"
sudo lxc config set core.https_allowed_headers "Content-Type"
sudo lxc config set core.trust_password true
sudo service lxd restart # sometimes is required
```

#### Generate authentication certificates (Self Signed)

```
openssl genrsa -out lxd.key 4096 # Generate a private key.
openssl req -new -key lxd.key -out lxd.csr # Create a certificate request.
openssl x509 -req -days 3650 -in lxd.csr -signkey lxd.key -out lxd.crt # Generate an auto signed certificate.
lxc config trust add lxd.crt # Tells LXC to use this certificate for auth.
```

Copy lxd.crt and lxd.key to installation folder and edit lxdconfig.conf settings.

---

### Run the server
#### Werkzeug *(dev only)*
```shell
python3 run.py
```

#### Gunicorn
```shell
gunicorn --bind :5000 app:app
```

#### uWSGI
```shell
uwsgi --socket :5000 --protocol=http --wsgi app:app
```

---

## Usage
### Requests

Set headers :

| key             | value              |
| :-------------- | :----------------- |
| `Content-Type`  | `application/json` |
| `Authorization` | `Bearer <token>`   |

---

## Documentation

* From your browser, get the swagger doc at [http://localhost:5000/doc/](http://localhost:5000/doc/)

## Configuration
You can store instance configuration in `instance/config.py`

or

Set your own env var :

`export LWP_CONFIG_FILE='/path/to/config/production.py'`
