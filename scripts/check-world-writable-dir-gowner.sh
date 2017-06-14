#!/bin/bash

COUNT=`find / -xdev -perm -002 -type d -fstype ext4  -exec ls -lLdg {} \;  | grep "root" | grep -v "/root" | wc -l`

if [ ${COUNT} -eq 0 ];then
	:
else
	exit 1
fi

