#!/bin/bash

WIFISET=`nmcli radio wifi`
if [ "${WIFISET}" == "enabled" ];then
	exit 1
fi

