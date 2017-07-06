#!/bin/bash

#Based on http://unix.stackexchange.com/questions/175146/apt-get-update-exit-status
#And http://unix.stackexchange.com/questions/19470/list-available-updates-but-do-not-install-them

if ! { apt-get update 2>&1 || echo E: update failed ;} | grep -q '^[WE]:';then
        echo update success
else
        echo update failure
        exit 1
fi

if [ "$(aptitude search '~U' | wc -l)" -gt 0 ];then
        echo Need-to-update
        exit 1
else 
        echo No-Need-to-update
        exit 0
fi
