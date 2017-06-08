#!/bin/bash

account_inactivity_lockday=$1

if sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/default/useradd | grep INACTIVE;then
        if [ $(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/default/useradd | grep INACTIVE | awk -F '=' '{printf $2}') -gt ${account_inactivity_lockday} ];then
                exit 1
        fi
else
        exit 1
fi
