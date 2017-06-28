#!/bin/bash

case $1 in
	aggregation-server)
		COUNT=`grep "^\*\.\*.*@" /etc/rsyslog.conf | wc -l`
		if [ ${COUNT} -eq 1 ]; then 
			:
		else
			exit 1
		fi
	;;
	imtcp)
		if grep imtcp /etc/rsyslog.conf  | grep -v "^#";then
			exit 1
		fi
	;;
esac
