#!/bin/bash

check_deny=`bash ./check-password.sh /etc/pam.d/common-auth pam_tally deny ge 3`
check_locktime=`bash ./check-password.sh /etc/pam.d/common-auth pam_tally lock_time ge 900`
ROOT_DENY_COUNT=`grep pam_tally /etc/pam.d/common-auth | grep -v "^#" | grep even_deny_root | wc -l`

if [ "${check_deny}"!="0" -o "${check_locktime}"!="0" ];then
	exit 1
elif [ ${ROOT_DENY_COUNT} -ne 0 ];then
	:
else
	exit 1	
fi
