#!/bin/bash

pushd ~/webapp/golang
make
popd

sudo systemctl restart mysql
sudo systemctl restart web-golang
sudo rm -rf /var/log/nginx/access.log
sudo systemctl restart nginx
sudo cat /var/log/nginx/access.log
