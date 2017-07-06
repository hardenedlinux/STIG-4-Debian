#!/bin/bash

if [ "$(dpkg -V | grep -c "^..5"`)" -gt 0 ];then
	exit 1
fi

