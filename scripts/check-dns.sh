#!/bin/bash

if grep "^hosts:.*files\|hosts:.*dns" /etc/nsswitch.conf;then
	COUNTDNSSER=`grep -c "^nameserver" /etc/resolv.conf`
	if [ "${COUNTDNSSER}" -lt 2 ];then
		exit 1
	fi
else
	exit 1
fi
