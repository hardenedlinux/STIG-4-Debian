#!/bin/bash

case $1 in
        active)
		ACTIVE=`dpkg -s auditd | grep "^Status:.install" | grep installed | wc -l`
		if [ ${ACTIVE} -eq 1 ];then
			:
		else
			exit 1
		fi
	;;
	enableflag)
		if [  $(auditctl -s | grep enabled | wc -l) -eq 0 ];then
			exit 1
		else
			FLAG=`auditctl -s | grep enabled | awk '{printf $2}'`
			if [ ${FLAG} -eq 2 -o ${FLAG} -eq 1 ];then
				:
			else
				exit 1
			fi
		fi
	
	;;
	remote_server)
		ISSET=`grep "^remote_server" /etc/audisp/audisp-remote.conf |  grep '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | wc -l`
		if [ ${ISSET} -eq 0 ];then
			exit 1
		fi
	;;
esac
