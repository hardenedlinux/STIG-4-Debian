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
		if dpkg -s auditd | grep -i "Status:.*install.*ok.*installed";then
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
			if [ "${SETVALUE}" == "yes" ];then
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
	PrintLastLog)
		if grep PrintLastLog /etc/ssh/sshd_config | grep -v "^#";then
			SETVALUE=`grep PrintLastLog /etc/ssh/sshd_config | grep -v "^#" | awk '{printf $2}'`
			if [ "${SETVALUE}" != "yes" ];then
				exit 1
			fi
		else
			exit 1
		fi
	;;
	IgnoreUserKnownHosts)
		if grep IgnoreUserKnownHosts /etc/ssh/sshd_config | grep -v "^#";then
			SETVALUE=`grep IgnoreUserKnownHosts /etc/ssh/sshd_config | grep -v "^#" | awk '{printf $2}'`
			if [ "${SETVALUE}" != "yes" ];then
				exit 1
			fi
		else
			exit 1
		fi
	;;
	macs)
		if grep -i "MACs.*hmac-sha2-256\|MACs.*hmac-sha2-512"  /etc/ssh/sshd_config;then
			:
		else
			exit 1
		fi
	;;
	pubkeypermissive)
		COUNT=`find /etc/ssh/ -type f -name "*.pub" -perm  /133  -exec ls -l {} \; | wc -l`
		if [ ${COUNT} -eq 0 ];then
			:
		else
			exit 1
		fi
	;;
	hostkeypermissive)
		COUNT=`find /etc/ssh/ -type f -name "*ssh_host*key" -perm  /177  -exec ls -l {} \; | wc -l`
		if [ ${COUNT} -eq 0 ];then
			:
		else
			exit 1
		fi
	;;
	GSSAPIAuthentication)
		if grep GSSAPIAuthentication /etc/ssh/sshd_config | grep -v "^#";then
                        SETVALUE=`grep GSSAPIAuthentication /etc/ssh/sshd_config | grep -v "^#" | awk '{printf $2}'`
                        if [ "${SETVALUE}" != "no" ];then
                                exit 1
                        fi
                else
                        exit 1
                fi
	;;
	KerberosAuthentication)
		if grep KerberosAuthentication /etc/ssh/sshd_config | grep -v "^#";then
                        SETVALUE=`grep KerberosAuthentication /etc/ssh/sshd_config | grep -v "^#" | awk '{printf $2}'`
                        if [ "${SETVALUE}" != "no" ];then
                                exit 1
                        fi
                else
                        exit 1
                fi
	;;
	StrictModes)
		if grep StrictModes /etc/ssh/sshd_config | grep -v "^#";then
                        SETVALUE=`grep StrictModes /etc/ssh/sshd_config | grep -v "^#" | awk '{printf $2}'`
                        if [ "${SETVALUE}" != "yes" ];then
                                exit 1
                        fi
                else
                        exit 1
                fi
	;;
	UsePrivilegeSeparation)
		if grep UsePrivilegeSeparation /etc/ssh/sshd_config | grep -v "^#";then
                        SETVALUE=`grep UsePrivilegeSeparation /etc/ssh/sshd_config | grep -v "^#" | awk '{printf $2}'`
                        if [ "${SETVALUE}" != "yes" -a "${SETVALUE}" != "sandbox" ];then
                                exit 1
                        fi
                else
                        exit 1
                fi
	;;
	Compression)
		if grep Compression /etc/ssh/sshd_config | grep -v "^#";then
                        SETVALUE=`grep Compression /etc/ssh/sshd_config | grep -v "^#" | awk '{printf $2}'`
                        if [ "${SETVALUE}" != "no" -a "${SETVALUE}" != "delayed" ];then
                                exit 1
                        fi
                else
                        exit 1
                fi
	;;
	X11Forwarding)
		if grep X11Forwarding /etc/ssh/sshd_config | grep -v "^#";then
                        SETVALUE=`grep X11Forwarding /etc/ssh/sshd_config | grep -v "^#" | awk '{printf $2}'`
                        if [ "${SETVALUE}" != "yes" ];then
                                exit 1
                        fi
                else
                        exit 1
                fi
        ;;

esac
