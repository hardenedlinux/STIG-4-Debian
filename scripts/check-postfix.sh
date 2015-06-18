#!/bin/bash

if [ "$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' -e 's/ //g' /etc/postfix/main.cf | grep inet_interfaces | awk -F '=' '{print $2}')" != "localhost" ];then
        exit 1
fi
