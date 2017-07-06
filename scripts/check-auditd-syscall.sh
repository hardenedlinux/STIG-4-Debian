#!/bin/bash

SYSCALLNAME=$1
COUNT=`auditctl -l | grep -c "^-a.*-S.*${SYSCALLNAME}"`

if [ "${COUNT}" -gt 0 ];then
	:
else
	exit 1
fi

