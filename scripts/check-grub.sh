#!/bin/bash

COUNT=`grep "set root" /boot/grub/grub.cfg | grep -v "hd0" | wc -l `

if [ ${COUNT} -eq 0 ];then
	:
else
	exit 1
fi

