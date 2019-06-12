#!/bin/bash

if [ -f "/etc/login.def" ];then
        VFAIL_DELAY=$1 # seconds

        RESULT=$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/login.defs | grep FAIL_DELAY)
        if [ $? -eq 0 ];then
                if [ "$(echo $RESULT | awk '{printf $2}')" -lt "${VFAIL_DELAY}" ];then
                        exit 1
                fi
        else
                exit 1
        fi

elif [ -f "/etc/pam.d/login" ];then
        VFAIL_DELAY=$(($1 * 1000000)) # microseconds

        RESULT=$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/pam.d/login | grep 'pam_faildelay.so' | grep -P -o "\bdelay\s*=\s*\d+")
        if [ $? -eq 0 ];then
                if [ "$(echo $RESULT | cut -d= -f2-)" -lt "${VFAIL_DELAY}" ];then
                        exit 1
                fi
        else
                exit 1
        fi

else
        exit 1
fi
