#!/bin/bash

if [ $(find / -xdev -type d -perm -0002 -uid +499 -print | wc -l) -gt 0 ];then
        exit 1
fi
