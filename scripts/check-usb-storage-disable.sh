#!/bin/bash

COUNT=`grep -i "install.*usb-storage.*/bin/true" /etc/modprobe.d/* | wc -l`

if [ ${COUNT} -ne 1 ];then 
	exit 1
fi


