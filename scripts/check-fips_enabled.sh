#!/bin/bash

if [ `cat /proc/sys/crypto/fips_enabled ` -eq 0 ];then
	exit 1
fi

