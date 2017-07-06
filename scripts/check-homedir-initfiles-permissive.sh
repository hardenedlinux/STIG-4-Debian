#!/bin/bash
for line in $(egrep ":[0-9]{4}:" /etc/passwd | cut -d: -f6)
do
	if [ ! -e "${line}" ];then
		exit 1
	else
		COUNT=`find "${line}" -type f  -name ".*" -perm  /037  -exec ls -l {} \; | wc -l`
		if [ "${COUNT}" -eq 0 ];then
			:
		else
			exit 1
		fi
	fi
done
