#!/bin/bash

MOUNTNAME=$1
case $2 in
        nodev)
                if [ "$(mount | grep ${MOUNTNAME} | wc -l)" != "$(mount | grep "${MOUNTNAME}.*nodev" | wc -l)" ];then
                        exit 1
                fi
	;;
	nosuid)
	        if [ "$(mount | grep  ${MOUNTNAME} | wc -l)" != "$(mount | grep "${MOUNTNAME}.*nosuid" | wc -l)" ];then
		        exit 1
		fi
	;;
esac
