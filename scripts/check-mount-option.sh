#!/bin/bash

MOUNTNAME=$1
case $2 in
        nodev)
                if [ "$(mount | grep -c "${MOUNTNAME}")" != "$(mount | grep -c "${MOUNTNAME}.*nodev")" ];then
                        exit 1
                fi
	;;
	nosuid)
	        if [ "$(mount | grep  -c "${MOUNTNAME}")" != "$(mount | grep -c "${MOUNTNAME}.*nosuid")" ];then
		        exit 1
		fi
	;;
esac
