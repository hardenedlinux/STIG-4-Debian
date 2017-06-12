#!/bin/bash

password_change_interval_day=$1

if [ -f "/etc/login.def" ];then

        RESULT=$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/login.defs | grep PASS_MIN_DAYS)
        if [ $? -eq 0 ];then
                if [ "$(echo $RESULT | awk '{printf $2}')" -lt "${password_change_interval_day}" ];then
                        exit 1
                fi  
        else
                exit 1
        fi  
else
        exit 1
fi
