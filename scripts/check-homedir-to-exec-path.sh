#!/bin/bash

# count file's owner is error command(example: username:test1 uid:1000 ):
# grep -d skip ":/home/test1"  /home/test1/.* | grep -v "#" | grep -v ".viminfo" | grep -v ".bash_history" | wc -l

for line in $(egrep ":[0-9]{4}:" /etc/passwd | cut -d: -f6)
do
	if [ ! -e "${line}" ];then
		exit 1
	else
		COUNT=`grep -d skip ":${line}"  "${line}"/.* | grep -v "#" | grep -v ".viminfo" | grep -v ".bash_history" | wc -l`
		if [ "${COUNT}" -gt 0 ];then
			exit 1
		fi
	fi
done
