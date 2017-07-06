#!/bin/bash

COUNT_SUM=`awk -F: '$5 > "${PASSWDMAXDAYS}" {print $1}' /etc/shadow | wc -l`

if [ "${COUNT_SUM}" -gt 0 ];then
	exit 1
fi

