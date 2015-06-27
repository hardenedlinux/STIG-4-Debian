#!/bin/bash

if grep -i "gpg" /etc/apt/apt.conf.d/* | sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' | grep -i "gpg.*check.*false";then
        exit 1
fi
