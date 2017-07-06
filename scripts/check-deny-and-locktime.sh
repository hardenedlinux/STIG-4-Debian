#!/bin/bash

CHECK_DENY=`bash ./check-password.sh /etc/pam.d/common-auth pam_tally2 deny ge 3`
CHECK_LOCKTIME=`bash ./check-password.sh /etc/pam.d/common-auth pam_tally2 lock_time ge 900`

if [ "${CHECK_DENY}" != "0" -o "${CHECK_LOCKTIME}" != "0" ];then
	exit 1
fi
