#!/bin/bash

COUNT=`grep -ic "install.*usb-storage.*/bin/true" /etc/modprobe.d/*`

if [ "${COUNT}" -ne 1 ];then 
	exit 1
fi


