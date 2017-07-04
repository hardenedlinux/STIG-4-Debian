#!/bin/bash

if [ "$(grep -c aide /etc/crontab /etc/cron.*/*)" -ne 0 ];then
        exit 1
fi
