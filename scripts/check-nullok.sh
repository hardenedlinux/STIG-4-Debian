#!/bin/bash

if [ -f "/etc/pam.d/system-auth" ];then
	sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/pam.d/system-auth | while read line;do 
		echo $line | grep nullok;
		if [ $? -eq 0 ];then
			exit 1
		fi
	done
	if [ $? -eq 1 ];then 
		exit 1
		if [ -f "/etc/pam.d/system-auth-ac" ];then
			sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/pam.d/system-auth-ac | while read line;do
			if [ $? -eq 0 ];then
				exit 1
			fi
			done
		fi
	fi
fi
