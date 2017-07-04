#!/bin/bash

ISINSTALLED=$(dpkg -s aide |  grep -ci "Status:.*install.*ok.*installed")
if [ "${ISINSTALLED}" -eq 0 ];then
	exit 1
fi

case $1 in
        acl)
		if [ "$(grep -v "^#" /etc/aide/aide.conf  | grep -c acl)" -eq 0 ];then
			exit 1
		fi
        ;;
        sha512)
		if [ "$(grep -v "^#" /etc/aide/aide.conf  | grep -c sha512)" -eq 0 ];then
			exit 1
		fi
        ;;
esac
