#!/bin/bash

case $1 in
        active)
		ACTIVE=`dpkg -s auditd | grep -ci "Status:.*install.*ok.*installed"`
		if [ "${ACTIVE}" -eq 1 ];then
			:
		else
			exit 1
		fi
	;;
	enableflag)
		if [  "$(auditctl -s | grep -c enabled)" -eq 0 ];then
			exit 1
		else
			FLAG=`auditctl -s | grep enabled | awk '{printf $2}'`
			if [ "${FLAG}" -eq 2 -o "${FLAG}" -eq 1 ];then
				:
			else
				exit 1
			fi
		fi
	
	;;
	remote_server)
		ISSET=`grep "^remote_server" /etc/audisp/audisp-remote.conf |  grep -c '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'`
		if [ "${ISSET}" -eq 1 ];then
			:
		else
			exit 1
		fi
	;;
	enable_krb5)
		ISSET=`grep -c "^enable_krb5.*=.*no" /etc/audisp/audisp-remote.conf`
		if [ "${ISSET}" -eq 1 ];then
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
		if [ "${SETSIZE}" -ge "${LEFTSIZE}" ];then
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
	tallylog)
		COUNT=`auditctl -l | grep -c /var/log/tallylog`
		if [ "${COUNT}" -eq 1 ];then
			:
		else
			exit 1
		fi
	;;
	faillock)
		COUNT=`auditctl -l | grep -c /var/run/faillock`
		if [ "${COUNT}" -eq 1 ];then
			:
		else
			exit 1
		fi
	;;
	lastlog)
		COUNT=`auditctl -l | grep -c /var/log/lastlog`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
        ;;
	passwd)
		COUNT=`auditctl -l | grep -c /usr/bin/passwd`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
        ;;
	unix_chkpwd)
		COUNT=`auditctl -l | grep -c /sbin/unix_chkpwd`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
        ;;
	gpasswd)
		COUNT=`auditctl -l | grep -c /usr/bin/gpasswd`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
        ;;
	chage)
		COUNT=`auditctl -l | grep -c /usr/bin/chage`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
        ;;
	su)
		COUNT=`auditctl -l | grep -c /bin/su`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
        ;;
	sudo)
		COUNT=`auditctl -l | grep -c /usr/bin/sudo`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
        ;;
	f-sudoers)
		COUNT=`auditctl -l | grep -c /etc/sudoers`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
        ;;
	newgrp)
		COUNT=`auditctl -l | grep -c /usr/bin/newgrp`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
        ;;
	chsh)
		COUNT=`auditctl -l | grep -c /usr/bin/chsh`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
        ;;
	sudoedit)
		COUNT=`auditctl -l | grep -c /usr/bin/sudoedit`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
        ;;
	mount)
		COUNT=`auditctl -l | grep -c /bin/mount`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
        ;;
	umount)
		COUNT=`auditctl -l | grep -c /bin/umount`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
        ;;
	postdrop)
		COUNT=`auditctl -l | grep -c /usr/sbin/postdrop`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
        ;;
	postqueue)
		COUNT=`auditctl -l | grep -c /usr/sbin/postqueue`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
        ;;
	crontab)
		COUNT=`auditctl -l | grep -c /usr/bin/crontab`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
        ;;
	pam_timestamp_check)
		COUNT=`auditctl -l | grep -c /usr/sbin/pam_timestamp_check`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
        ;;
	insmod)
		COUNT=`auditctl -l | grep -c /sbin/insmod`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
        ;;
	rmmod)
		COUNT=`auditctl -l | grep -c /sbin/rmmod`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
        ;;
	modprobe)
		COUNT=`auditctl -l | grep -c /sbin/modprobe`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
        ;;
	f-passwd)
		COUNT=`auditctl -l | grep -c /etc/passwd`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
        ;;
	network_failure_action)
                if grep -i "network_failure_action.*syslog\|network_failure_action.*single\|network_failure_action.*halt" /etc/audisp/audisp-remote.conf;then
	                :
                else
                	exit 1
                fi
        ;;
	f-gshadow)
		COUNT=`auditctl -l | grep -c /etc/gshadow`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
	;;
	f-group)
		COUNT=`auditctl -l | grep -c /etc/group`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
	;;
	f-shadow)
		COUNT=`auditctl -l | grep -c /etc/shadow`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
	;;
	f-opasswd)
		if [ "$2" -eq 0 ];then
			COUNT=`auditctl -l | grep -c /etc/opasswd`
                	if [ "${COUNT}" -eq 1 ];then
                        	:
                	else
                        	exit 1
                	fi
		elif [ "$2" -eq 1 ];then
                        COUNT=`auditctl -l | grep -c /etc/security/opasswd`
                        if [ "${COUNT}" -eq 1 ];then
                                :
                        else
                                exit 1
                        fi
		else
			exit 1
		fi
	;;
	ssh-keysign)
		COUNT=`auditctl -l | grep -c /usr/lib/openssh/ssh-keysign`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
	;;
	gnome-pty-helper)
		COUNT=`auditctl -l | grep -c gnome-pty-helper`
                if [ "${COUNT}" -eq 1 ];then
                        :
                else
                        exit 1
                fi
	;;
esac
