#!/bin/bash

if [ $(find /etc/cron.d*/ -name logrotate | wc -l) -eq 0 ];then
        exit 1
fi
