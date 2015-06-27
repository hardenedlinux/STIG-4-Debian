#!/bin/bash

if [ -f /etc/systemd/system/ctrl-alt-del.target ];then
        if ! ls -l /etc/systemd/system/ctrl-alt-del.target | grep "/dev/null";then
                exit 1
        fi
else
        exit 1
fi
