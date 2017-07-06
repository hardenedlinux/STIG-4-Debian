#!/bin/bash
while read line ;do
if [ -z "`echo "$line" | awk -F: '{printf $6}'`" ];then
	exit 1
fi
done < /etc/passwd

