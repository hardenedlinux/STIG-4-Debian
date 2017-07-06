#!/bin/bash

PWD_CHANGE_INTERVAL_DAY=$1

if [ -f "/etc/login.def" ];then

        RESULT=$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/login.defs | grep PASS_MIN_DAYS)
        if [ $? -eq 0 ];then
                if [ "$(echo "$RESULT" | awk '{printf $2}')" -lt "${PWD_CHANGE_INTERVAL_DAY}" ];then
                        exit 1
                fi  
        else
                exit 1
        fi  
else
        exit 1
fi
