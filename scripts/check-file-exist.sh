#!/bin/bash

# $1 is will search file name.

COUNT=`find / -name "$1" | wc -l`

if [ "${COUNT}" -ne 0 ];then
	exit 1
fi
