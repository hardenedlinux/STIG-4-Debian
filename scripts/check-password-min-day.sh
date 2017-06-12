#!/bin/bash

if [ `awk -F: '$4 < 1 {print $1}' /etc/shadow | wc -l` -gt 0 ];then
	exit 1
fi
