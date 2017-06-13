#!/bin/bash

# count initialization file's owner is error command(example: username:test1 uid:1000 ):
# find /home/test1/ -type f -name ".*" \! -uid 1000 -a \! -uid 0 -exec ls -l {} \;

for line in $(egrep ":[0-9]{4}:" /etc/passwd | cut -d: -f6)
do
	if [ ! -e ${line} ];then
		exit 1
	else
		cur_user_uid=`grep "${line}:" /etc/passwd | cut -d: -f3`
		owner_check_err_count=`find ${line} -type f -name ".*" \! -uid ${cur_user_uid} -a \! -uid 0 -exec ls -l {} \; | wc -l `
		if [ ${owner_check_err_count} -gt 0 ];then
			exit 1
		fi
	fi
done
