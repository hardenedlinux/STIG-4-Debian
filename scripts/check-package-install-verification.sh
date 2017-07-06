#!/bin/bash

COUNT=0
case $1 in
	repository)
		COUNT=`grep -v "^#" /etc/apt/ -r | grep -ic allowunauthenticated`
		if [ "${COUNT}" -ne 0 ];then
			exit 1
		fi
	;;
	local)
		COUNT=`grep -v "#.*no-debsig" /etc/dpkg/ -r | grep -ci no-debsig`
		if [ "${COUNT}" -ne 0 ];then
			exit 1
		fi
	;;
esac

