#!/bin/bash

if dpkg -s audispd-plugins > /dev/null 2>&1;then
        if ! sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/audisp/plugins.d/syslog.conf | grep -i "active.*yes";then
                exit 1
        fi       
else
        exit 1
fi
