#1/bin/bash

if [ $(grep aide /etc/crontab /etc/cron.*/* | wc -l) -ne 0 ];then
        exit 1
fi
