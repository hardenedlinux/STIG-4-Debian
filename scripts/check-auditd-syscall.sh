#!/bin/bash

SYSCALLNAME=$1
COUNT=`auditctl -l | grep "^-a.*-S.*${SYSCALLNAME}" | wc -l`

if [ ${COUNT} -gt 0 ];then
	:
else
	exit 1
fi

