#!/bin/bash

COUNT=`dpkg -s xorg | grep "^Status:.install" | grep installed | wc -l`

if [ ${COUNT} -ne 1 ];then
	exit 1
fi

