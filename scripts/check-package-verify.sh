#!/bin/bash

if [ `dpkg -V | grep "^..5" | wc -l` -gt 0 ];then
	exit 1
fi

