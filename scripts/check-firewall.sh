#!/bin/bash

COUNT=`iptables -S | wc -l`
if [ ${COUNT} -lt 3 ];then
	exit 1
fi

