#!/bin/bash

SYSCALLNAME=$1

if grep -i "^-a.*-S.*${SYSCALLNAME}" /etc/audit/audit.rules ;then
	:
else
	exit 1
fi

