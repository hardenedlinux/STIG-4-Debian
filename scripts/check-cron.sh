#!/bin/bash

case $1 in
	allowfileown)
		if [ -e /etc/cron.allow ];then
			if [ $(stat -c "%G" /etc/cron.allow) != "root" ];then
				exit 1
			fi
		fi
	;;
	allowfilegown)
		if [ -e /etc/cron.allow ];then
			if [ $(stat -c "%U" /etc/cron.allow) != "root" ];then
			exit 1
			fi
		fi
	;;
esac
