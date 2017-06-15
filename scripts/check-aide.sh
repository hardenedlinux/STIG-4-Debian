#!/bin/bash

ISINSTALLED=`dpkg -s aide | grep "^Status:" | grep installed | wc -l`
if [ ${ISINSTALLED} -eq 0 ];then
	exit 1
fi

case $1 in
        acl)
		if [ $(grep acl /etc/aide/aide.conf  | grep -v "^#" | wc -l) -eq 0 ];then
			exit 1
		fi
        ;;
        sha512)
		if [ $(grep sha512 /etc/aide/aide.conf  | grep -v "^#" | wc -l) -eq 0 ];then
			exit 1
		fi
        ;;
esac
