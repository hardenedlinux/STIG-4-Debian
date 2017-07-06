#!/bin/bash

case $1 in
	allowfileown)
		if [ -e /etc/cron.allow ];then
			if [ "$(stat -c "%G" /etc/cron.allow)" != "root" ];then
				exit 1
			fi
		fi
	;;
	allowfilegown)
		if [ -e /etc/cron.allow ];then
			if [ "$(stat -c "%U" /etc/cron.allow)" != "root" ];then
			exit 1
			fi
		fi
	;;
	cronlog)
		if grep "^cron\.\*.*/var/log/cron.log" /etc/rsyslog.conf;then
			LINE1=`grep "^cron\.\*.*/var/log/cron.log" /etc/rsyslog.conf -n | awk -F : '{print $1}'`
			if grep "^\*\.\*.*~" /etc/rsyslog.conf;then
				LINE2=`grep "^\*\.\*.*~" /etc/rsyslog.conf  -n | awk -F : '{print $1}'`
				if [ "${LINE1}" -gt "${LINE2}" ];then
					exit 1
				fi
			fi
		else
			exit 1
		fi
		
	;;
esac
