#!/bin/bash

for line in $(egrep ":[0-9]{4}:" /etc/passwd | cut -d: -f6)
do
	if [ ! -e "${line}" ];then
		exit 1
	else
		if [ `stat -c "%g" "${line}"` -ne `grep "${line}:" /etc/passwd | cut -d: -f4` ];then
			exit 1
		fi
	fi
done
