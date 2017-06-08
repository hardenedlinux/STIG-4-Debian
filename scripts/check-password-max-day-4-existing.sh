#!/bin/bash
passmaxdays=$1

count_sum=`awk -F: '$5 > "${passmaxdays}" {print $1}' /etc/shadow | wc -l`

if [ ${count_sum} -gt 0 ];then
	exit 1
fi

