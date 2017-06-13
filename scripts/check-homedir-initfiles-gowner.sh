#!/bin/bash

# count file's group owner is error command(example: username:test1 uid:1000 ):
# find /home/test1 -type f -name ".*" \! -gid 1000 -a \! -gid 0 -exec ls -l {} \; 

for line in $(egrep ":[0-9]{4}:" /etc/passwd | cut -d: -f6)
do
	if [ ! -e ${line} ];then
		exit 1
	else
		cur_user_gid=`grep "${line}:" /etc/passwd | cut -d: -f4`
		owner_check_err_count=`find ${line} -type f -name ".*" \! -gid ${cur_user_gid} -a \! -gid 0 -exec ls -l {} \; | wc -l `
		if [ ${owner_check_err_count} -gt 0 ];then
			exit 1
		fi
	fi
done
