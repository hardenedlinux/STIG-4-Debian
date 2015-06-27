#!/bin/bash

if sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/default/useradd | grep INACTIVE;then
        if [ $(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/default/useradd | grep INACTIVE | awk -F '=' '{printf $2}') -gt 35 ];then
                exit 1
        fi
else
        exit 1
fi
