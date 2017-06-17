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
		if [ ${ISSET} -eq 1 ];then
			:
		else
			exit 1
		fi
	;;
	enable_krb5)
		ISSET=`grep "^enable_krb5.*=.*no" /etc/audisp/audisp-remote.conf | wc -l`
		if [ ${ISSET} -eq 1 ];then
			:
		else
			exit 1
		fi
	;;
	disk_full_error_action)
                if grep -i "disk_full_action.*syslog\|disk_full_action.*single\|disk_full_action.*halt" /etc/audit/auditd.conf;then
			if grep -i "disk_error_action.*syslog\|disk_error_action.*single\|disk_error_action.*halt" /etc/audit/auditd.conf;then
				:
			else
				exit 1
			fi
		else
                        exit 1
                fi
        ;;
	space_left)
		DISKSIZE=`df  -B 1m /var/log/audit/ | grep -v "Filesystem" | awk '{printf $2}'`
		LEFTSIZE=`bc <<<${DISKSIZE}*0.25`
		SETSIZE=`grep "^space_left.=.*"  /etc/audit/auditd.conf | awk '{printf $3}'`
		if [ ${SETSIZE} -ge ${LEFTSIZE} ];then
			:
		else
			exit 1
		fi
	;;
	space_left_action)
                EXIST=$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/audit/auditd.conf | sed -e 's/\ //'g | grep $1)
                if [ $? -eq 0 ];then
                        ACTION=$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/audit/auditd.conf | sed -e 's/\ //'g | grep $1 | awk -F '=' '{print $2}')
                        if [ "${ACTION,,}" != "email" ];then
                            exit 1
                        fi
                else
                        exit 1
                fi
        ;;
	action_mail_acct)
                EXIST=$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/audit/auditd.conf | sed -e 's/\ //'g | grep $1)
                if [ $? -eq 0 ];then
                        ACCOUNT=$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/audit/auditd.conf | sed -e 's/\ //'g | grep $1 | awk -F '=' '{print $2}')
                        if [ "${ACCOUNT,,}" != "root" ];then
                            exit 1
                        fi
                else
                        exit 1
                fi
        ;;
esac
