#!/bin/bash

COUNT=`ip link | grep -ic promisc`
if [ "${COUNT}" -ne 0 ];then
	exit 1
fi

