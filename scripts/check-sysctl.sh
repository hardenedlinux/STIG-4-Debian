#!/bin/bash
OPTION=$1
COMPARE=$2
CONDITION=$3

if [ "$(sysctl $OPTION | awk '{print $3}')" -$(echo $COMPARE) "$CONDITION" ];then
        exit 1
fi
