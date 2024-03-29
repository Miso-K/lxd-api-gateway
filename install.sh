#!/usr/bin/env bash

setupEnvrionment () {
printf '=============Setup the environment=============== \n'
sudo apt-get update
sudo apt-get install -y python3 python3-pip
pip3 install virtualenv
sudo apt-get install -y nginx
sudo apt-get install -y redis-server
}

setupApp () {
printf '===============Setup the Application ================== \n'
cd /home/ubuntu
git clone https://github.com/Miso-K/lxd-api-gateway
cd lxd-api-gateway
virtualenv -p python3 lgw-env
source lgw-env/bin/activate
pip3 install -r requirements.txt
}

configureNginx () {
printf '==================== Configure nginx =================== \n'
# Create the nginx configuration
sudo bash -c 'cat > /etc/nginx/sites-available/lxd-api-gateway <<EOF
server {
listen 80;

#server_name api.example.com;

# Allow access to the ACME Challenge for Lets Encrypt
location ^~ /.well-known/acme-challenge {
   allow all;
root /var/www/acme;
}

location / {
    proxy_pass http://127.0.0.1:5000/;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  }

# Use this config instead with https
#location / {
#    return 301 https://\$server_name\$request_uri;
#  }
}

#server {
#listen 443 ssl;
#server_name api.example.com;

# Use this config for self signed certificates
#ssl_certificate /etc/nginx/ssl/nginx.crt;
#ssl_certificate_key /etc/nginx/ssl/nginx.key;

# Use this config for letsencrypt certificates
#ssl_certificate /etc/letsencrypt/live/api.example.com/fullchain.pem;
#ssl_certificate_key /etc/letsencrypt/live/api.example.com/privkey.pem;

# This section allow console connection for "server1" and "IP"
#location /server1/1.0/operations/ {
#     proxy_pass https://127.0.0.1:8443/1.0/operations/;
#     proxy_set_header Upgrade \$http_upgrade;
#     proxy_set_header Connection "upgrade";
#  }

# This section allow console connection for "server2" and "IP"
#location /server2/1.0/operations/ {
#     proxy_pass https://127.0.0.2:8443/1.0/operations/;
#     proxy_set_header Upgrade \$http_upgrade;
#     proxy_set_header Connection "upgrade";
#  }


#location /api/ {
#    proxy_pass http://127.0.0.1:5000/api/;
#    proxy_set_header Host \$host;
#    proxy_set_header X-Forwarded-Proto \$scheme;
#    proxy_set_header X-Real-IP \$remote_addr;
#    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
#  }
#}

EOF
'
sudo rm -rf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
sudo ln -s /etc/nginx/sites-available/lxd-api-gateway /etc/nginx/sites-enabled/
sudo systemctl restart nginx
sudo mkdir -p /var/www/acme
}

setupStartScript () {
printf '=============== Create a startup script =============== \n'
# create a .env file for the environment variables
PASSWD=$(openssl rand -base64 10)
S_KEY=$(openssl rand -base64 25)
J_KEY=$(openssl rand -base64 25)
sudo bash -c "cat > /home/ubuntu/lxd-api-gateway/\.env <<EOF
export SECRET_KEY='$S_KEY'
export JWT_SECRET_KEY='$J_KEY'
export ADMIN_PASSWORD='$PASSWD'
EOF
"

# create folder for logs
mkdir /home/ubuntu/lxd-api-gateway/logs
chown ubuntu:ubuntu -R /home/ubuntu/lxd-api-gateway/logs

# create a startup script to start the virtual environment, load the environment variables and start the app
sudo bash -c 'cat > /home/ubuntu/lxd-api-gateway/startenv.sh <<EOF
#!/bin/bash
cd /home/ubuntu
ls
cd lxd-api-gateway
source lgw-env/bin/activate
source .env
gunicorn app:app -b 127.0.0.1:5000 --preload --log-level info --access-logfile /home/ubuntu/lxd-api-gateway/logs/access.log --error-logfile /home/ubuntu/lxd-api-gateway/logs/error.log
EOF
'
}

setupAppDB () {
printf '============ Setup lxd-api-gateway database ============= \n'
source /home/ubuntu/lxd-api-gateway/.env
python3 install/setup.py
}

setupStartService () {
printf '============ Configure startup service ============= \n'
# Create service that starts the app from the startup script
sudo bash -c 'cat > /etc/systemd/system/lxd-api-gateway.service <<EOF
[Unit]
Description=lxd-api-gateway startup service
After=network.target
[Service]
User=ubuntu
ExecStart=/bin/bash /home/ubuntu/lxd-api-gateway/startenv.sh
Restart=always
[Install]
WantedBy=multi-user.target
EOF
'

sudo chown ubuntu:ubuntu -R /home/ubuntu/lxd-api-gateway/
sudo chmod 744 /home/ubuntu/lxd-api-gateway/startenv.sh
sudo chmod 664 /etc/systemd/system/lxd-api-gateway.service
sudo systemctl daemon-reload
sudo systemctl enable lxd-api-gateway.service
sudo systemctl start lxd-api-gateway.service
}

createCertificates () {
printf '=============== Generate certificates =============== \n'
openssl genrsa -out lxd.key 4096 # Generate a private key.
openssl req -new -key lxd.key -out lxd.csr # Create a certificate request.
openssl x509 -req -days 3650 -in lxd.csr -signkey lxd.key -out lxd.crt # Generate an auto signed certificate.
echo -e "\nPlease set certificate for lxd:"
echo -e "lxc config trust add lxd.crt"
echo -e "\nPlease configure your lxd server:"
echo -e "sudo lxc config set core.https_address [::]:8443"
echo -e "sudo lxc config set core.https_allowed_origin \"*\""
echo -e "sudo lxc config set core.https_allowed_methods \"GET, POST, PUT, DELETE, OPTIONS\""
echo -e "sudo lxc config set core.https_allowed_headers \"Content-Type\""
echo -e "sudo lxc config set core.trust_password true"
echo -e "sudo service lxd restart"
}

setupAppConfig () {
printf '=============== Create lxdconfig.conf file =============== \n'
# Create default lxdconfig for lxd-api-gateway
sudo bash -c 'cat > /home/ubuntu/lxd-api-gateway/lxdconfig.conf <<EOF
[remote]
endpoint = https://127.0.0.1:8443
cert_crt = lxd.crt
cert_key = lxd.key
verify = False
[app]
production_name = LXDmanager.com
EOF
'

}

testAdminLogin () {
printf '=============== Test Admin login access =============== \n'
response=$(curl -so /dev/null -w '%{response_code}' -X POST "http://localhost/api/v1/auth" -H "Content-Type: application/json" -d '{ "username": "admin", "password": "'$PASSWD'"}')
case "$response" in
        200) printf "Received: HTTP $response -> Admin Login test SUCCESSFUL\n" ;;
        401) printf "Received: HTTP $response -> Wrong username or password\n" ;;
        404) printf "Received: HTTP $response -> Not Found\n" ;;
          *) printf "Received: HTTP $response \n" ;;
esac
}

run () {
setupEnvrionment
setupApp
configureNginx
setupStartScript
setupAppDB
setupStartService
createCertificates
setupAppConfig
testAdminLogin
}
run

echo -e "\nNew admin password is: $PASSWD"