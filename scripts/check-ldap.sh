#!/bin/bash

case $1 in 
	tls_cacertfile)
		if [ -e /etc/pam_ldap.conf ];then
			if grep -v "^#" /etc/pam_ldap.conf | grep -i "tls_cacertfile";then
        			if [ -e "$(grep -v "^#" /etc/pam_ldap.conf | grep -i "tls_cacertfile" | awk '{print $2}')" ];then
					:
				else
					exit 1
				fi
			else
				exit 1
			fi
		fi
	;;
	tls_cacertdir)
		if [ -e /etc/pam_ldap.conf ];then
			if grep -v "^#" /etc/pam_ldap.conf | grep -i "tls_cacertdir";then
	                        if [ -e "$(grep -v "^#" /etc/pam_ldap.conf | grep -i "tls_cacertdir" | awk '{print $2}')" ];then
        	                        :
                	        else
                        	        exit 1
                        	fi
			else
				exit 1
			fi
                fi
	;;
esac
