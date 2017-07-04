#!/bin/bash

if [ "$(awk -F: '($3 == 0) {print}' /etc/passwd | wc -l)" -gt 1 ];then
        exit 1
else
        if [ "$(awk -F: '($3 == 0) {print}' /etc/passwd | awk  -F ':' '{printf $1}')" == "root" ];then
                exit 0
	else 
	        exit 1
	fi
fi
