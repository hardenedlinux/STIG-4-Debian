#!/bin/bash

case $1 in
        nodev)
                if [ "$(mount | grep nfs | wc -l)" != "$(mount | grep "nfs.*nodev" | wc -l)" ];then
                        exit 1
                fi
	;;
	nosuid)
	        if [ "$(mount | grep nfs | wc -l)" != "$(mount | grep "nfs.*nosuid" | wc -l)" ];then
		        exit 1
		fi
	;;
esac
