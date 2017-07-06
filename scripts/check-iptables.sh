#!/bin/bash

case $1 in 
	iptables-ins)
		COUNT=`iptables -S | wc -l`
		if [ "${COUNT}" -lt 3 ];then
			exit 1
		fi
	;;
	iptables-dos)
		COUNT=`iptables -S | grep "\-m.*limit" | grep -c "\-\-limit-burst"`

		if [ "${COUNT}" -eq 0 ];then
			exit 1
		fi
 	;;
esac

