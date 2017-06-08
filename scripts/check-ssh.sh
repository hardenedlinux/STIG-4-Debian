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
esac
