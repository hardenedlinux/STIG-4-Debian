#!/bin/bash
case $1 in
        Protocol)
                if [ "$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/ssh/sshd_config | grep -w "^Protocol" | awk '{print $2}')" -ne 2 ];then
                        exit 1
                fi
        ;;
        rhosts)
                if [ "$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/ssh/sshd_config | grep -i IgnoreRhosts | awk '{print $2}')" != "yes" ];then
                        exit 1
                fi
        ;;
        hostauth)
                if [ "$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/ssh/sshd_config | grep -i HostbasedAuthentication | awk '{print $2}')" != "no" ];then
                        exit 1
                fi
        ;;
        permitroot)
                if [ "$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/ssh/sshd_config | grep -i PermitRootLogin | awk '{print $2}')" != "no" ];then
                        exit 1
                fi
        ;;
        emptypassword)
                if [ "$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/ssh/sshd_config | grep -i PermitEmptyPasswords | awk '{print $2}')" != "no" ];then
                        exit 1
                fi
        ;;
        emptypasswordenvironment)
                if [ "$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/ssh/sshd_config | grep -i PermitEmptyPasswords | awk '{print $2}')" != "no" ];then
                        exit 1
                fi
        ;;
	ciphers)
		if grep -i "Ciphers.*aes128-ctr\|Ciphers.*aes256-ctr\|Ciphers.*aes192-ctr" /etc/ssh/sshd_config;then
			:
		else
			exit 1 
		fi
	;;
	banner)
		if grep -i banner /etc/ssh/sshd_config | grep -v "^#";then
			:
		else
			exit 1
		fi
	;;
	installed)
		if dpkg -s auditd | grep "^Status:.install" | grep installed;then
			:
		else
			exit 1
		fi	
	;;
	sshd_status)
		if systemctl status sshd | grep "Active:.*(running)";then
			:
		else
			exit 1
		fi 
	;;
	ClientAliveInterval)
		if grep ClientAliveInterval /etc/ssh/sshd_config | grep -v "^#";then
			INTERVAL=`grep ClientAliveInterval /etc/ssh/sshd_config | grep -v "^#" | awk '{printf $2}'`
			if [ ${INTERVAL} -lt 600 ];then
				exit 1
			fi
		else
			exit 1
		fi
	;;
	RhostsRSAAuthentication)
		if grep RhostsRSAAuthentication /etc/ssh/sshd_config | grep -v "^#";then
			SETVALUE=`grep RhostsRSAAuthentication /etc/ssh/sshd_config | grep -v "^#" | awk '{printf $2}'`
			if [ "${SETVALUE}" == "no" ];then
				exit 1
			fi
		else
			exit 1
		fi
	;;
	ClientAliveCountMax)
		if grep ClientAliveCountMax /etc/ssh/sshd_config | grep -v "^#";then
			SETVALUE=`grep ClientAliveCountMax /etc/ssh/sshd_config | grep -v "^#" | awk '{printf $2}'`
			if [ ${SETVALUE} -ne 0 ];then
				exit 1
			fi
		else
			exit 1
		fi
	;;
	IgnoreRhosts)
		if grep IgnoreRhosts /etc/ssh/sshd_config | grep -v "^#";then
			SETVALUE=`grep IgnoreRhosts /etc/ssh/sshd_config | grep -v "^#" | awk '{printf $2}'`
			if [ "${SETVALUE}" == "no" ];then
				exit 1
			fi
		else
			exit 1
		fi
	;;
esac
