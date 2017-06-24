#!/bin/bash

COUNT=0
case $1 in
	repository)
		COUNT=`grep -i allowunauthenticated /etc/apt/ -r | grep -v "^#" | wc -l`
		if [ ${COUNT} -ne 0 ];then
			exit 1
		fi
	;;
	local)
		COUNT=`grep no-debsig /etc/dpkg/ -r | grep -v "#.*no-debsig" | wc -l`
		if [ ${COUNT} -ne 0 ];then
			exit 1
		fi
	;;
esac

