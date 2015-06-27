#!/bin/bash

if [ $(find / -xdev -type d -perm -002 \! -perm -1000 | wc -l) -gt 0 ];then
        exit 1
fi
