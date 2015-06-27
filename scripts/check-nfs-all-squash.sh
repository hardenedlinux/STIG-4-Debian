#!/bin/bash

if sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/exports | grep -i  "all_squash";then
        exit 1
fi
