#!/bin/bash

# count file's group owner is error command(example: username:test1 uid:1000 ):
# find /home/test1 -type f -name ".*" \! -gid 1000 -a \! -gid 0 -exec ls -l {} \; 

for line in $(egrep ":[0-9]{4}:" /etc/passwd | cut -d: -f6)
do
	if [ ! -e "${line}" ];then
		exit 1
	else
		CUR_USER_GID=`grep "${line}:" /etc/passwd | cut -d: -f4`
		OWNER_CHECK_ERR_COUNT=`find "${line}" -type f -name ".*" \! -gid "${CUR_USER_GID}" -a \! -gid 0 -exec ls -l {} \; | wc -l `
		if [ "${OWNER_CHECK_ERR_COUNT}" -gt 0 ];then
			exit 1
		fi
	fi
done
