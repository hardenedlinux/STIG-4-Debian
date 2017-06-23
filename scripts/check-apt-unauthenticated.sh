#!/bin/bash

COUNT=`grep -i allowunauthenticated /etc/apt/ -r | grep -v "^#" | wc -l`

if [ ${COUNT} -ne 0 ];then
	exit 1
fi

