#!/bin/sh
sudo mv /var/log/nginx/access.log /var/log/nginx/access.log.$(date +"%Y%m%d_%H%M")
sudo systemctl restart nginx
sudo systemctl restart isubata.php.service
