#!/bin/sh
sudo alp -f /var/log/nginx/access.log --sum -r --aggregates="/icons/.*","/fonts/.*","/history/.*","/profile/.*","/channel/.*" | cat | slackcat --channel "general" --filename "alp_output_$(date +'%H%M%s').txt"
