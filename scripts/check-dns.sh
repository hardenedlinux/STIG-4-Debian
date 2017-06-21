#!/bin/bash

if grep "^hosts:.*files\|hosts:.*dns" /etc/nsswitch.conf;then
	COUNTDNSSER=`grep "^nameserver" /etc/resolv.conf | wc -l`
	if [ ${COUNTDNSSER} -lt 2 ];then
		exit 1
	fi
else
	exit 1
fi
