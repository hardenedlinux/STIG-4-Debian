#!/bin/bash

check_deny=`bash ./check-password.sh /etc/pam.d/common-auth pam_tally deny ge 3`
check_locktime=`bash ./check-password.sh /etc/pam.d/common-auth pam_tally lock_time ge 900`

if [ "${check_deny}"="0" -o "${check_locktime}"="0" ];then
	exit 1
fi
