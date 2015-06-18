#!/bin/bash

if [ -f "/etc/securetty" ];then
        grep '^ttyS[0-9]' /etc/securetty
else
        exit 0
fi
