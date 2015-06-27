#!/bin/bash

if [ "$(find / -xdev -type f -perm -002 | wc -l)" -ne 0 ];then
        exit 1
fi
