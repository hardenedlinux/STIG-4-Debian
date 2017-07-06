#!/bin/bash

if [ "$(grep -i tmout /etc/bash.bashrc | grep -v "^#" | wc -l)" -ne 0 ]; then
	VTMOUT=`grep -i tmout /etc/bash.bashrc | awk -F = '{printf $2}'`
	if [ "${VTMOUT}" -lt 600 ];then	
		exit 1
	fi
elif [ "$(grep -i tmout /etc/profile | grep -v "^#" | wc -l)" -ne 0 ]; then 
        VTMOUT=`grep -i tmout /etc/profile | awk -F = '{printf $2}'`
        if [ "${VTMOUT}" -lt 600 ];then
                exit 1
        fi
else
	exit 1
fi

