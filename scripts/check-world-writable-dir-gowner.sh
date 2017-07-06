#!/bin/bash

COUNT=`find / -xdev -perm -002 -type d -fstype ext4  -exec ls -lLdg {} \;  | grep -v "/root" | grep -c "root"`

if [ "${COUNT}" -eq 0 ];then
	:
else
	exit 1
fi

