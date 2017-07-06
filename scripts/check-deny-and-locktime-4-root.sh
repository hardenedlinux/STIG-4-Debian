#!/bin/bash

CHECK_DENY=`bash ./check-password.sh /etc/pam.d/common-auth pam_tally2 deny ge 3`
CHECK_LOCKTIME=`bash ./check-password.sh /etc/pam.d/common-auth pam_tally2 lock_time ge 900`
ROOT_DENY_COUNT=`grep pam_tally2 /etc/pam.d/common-auth | grep -v "^#" | grep -c even_deny_root`

if [ "${CHECK_DENY}" != "0" -o "${CHECK_LOCKTIME}" != "0" ];then
	exit 1
elif [ "${ROOT_DENY_COUNT}" -ne 0 ];then
	:
else
	exit 1	
fi
