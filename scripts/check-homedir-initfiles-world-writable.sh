#!/bin/bash

COUNT=`find /home/*/* -type f -perm -002 -exec ls -l {} \; | wc -l`
if [ "${COUNT}" -eq 0 ];then
	:
else
	exit 1
fi
