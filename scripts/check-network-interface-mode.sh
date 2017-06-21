#!/bin/bash

COUNT=`ip link | grep -i promisc | wc -l`
if [ ${COUNT} -ne 0 ];then
	exit 1
fi

