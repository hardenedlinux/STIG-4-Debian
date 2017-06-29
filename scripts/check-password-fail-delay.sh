#!/bin/bash

VFAIL_DELAY=$1

if [ -f "/etc/login.def" ];then

        RESULT=$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/login.defs | grep FAIL_DELAY)
        if [ $? -eq 0 ];then
                if [ "$(echo $RESULT | awk '{printf $2}')" -lt "${VFAIL_DELAY}" ];then
                        exit 1
                fi  
        else
                exit 1
        fi  
else
        exit 1
fi
