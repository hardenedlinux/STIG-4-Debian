#!/bin/bash

if [ -f "/etc/pam.d/common-auth" ];then
	COUNT=`grep pam_unix /etc/pam.d/common-auth  | grep -v "^#" | grep nullok  | wc -l`
	if [ ${COUNT} -ge 1 ];then	
		exit 1
	fi
fi

