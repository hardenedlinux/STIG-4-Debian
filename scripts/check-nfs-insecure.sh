#!/bin/bash

if ! sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/exports | grep insecure_locks;then
        exit 1
fi
