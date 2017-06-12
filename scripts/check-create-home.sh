#!/bin/bash

if [ "`grep "^CREATE_HOME" /etc/login.defs | awk '{printf $2}'`" != "yes" ];then
	exit 1
fi
