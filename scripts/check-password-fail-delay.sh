#!/bin/bash

fail_delay=$1

if [ -f "/etc/login.def" ];then

        RESULT=$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/login.defs | grep FAIL_DELAY)
        if [ $? -eq 0 ];then
                if [ "$(echo $RESULT | awk '{printf $2}')" -lt "${fail_delay}" ];then
                        exit 1
                fi  
        else
                exit 1
        fi  
else
        exit 1
fi
