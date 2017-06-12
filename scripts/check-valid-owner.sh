#!/bin/bash

if [ `find / -xdev -fstype ext4 -nouser | wc -l` -gt 0 ];then
	exit 1
fi

