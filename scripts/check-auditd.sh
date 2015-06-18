#!/bin/bash

case $1 in
        num_logs)
                EXIST=$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/audit/auditd.conf | sed -e 's/\ //'g | grep $1)
                if [ $? -eq 0 ];then
                        if [ $(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/audit/auditd.conf | sed -e 's/\ //'g | grep $1 | awk -F '=' '{print $2}') -$2 $3 ];then
                            exit 1
                        fi
                else
                        exit 1
                fi
            ;;
        max_log_file)
                EXIST=$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/audit/auditd.conf | sed -e 's/\ //'g | grep $1=)
                if [ $? -eq 0 ];then
                        if [ $(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/audit/auditd.conf | sed -e 's/\ //'g | grep $1= | awk -F '=' '{print $2}') -$2 $3 ];then
                            exit 1
                        fi
                else
                        exit 1
                fi
            ;;
        max_log_file_action)
                EXIST=$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/audit/auditd.conf | sed -e 's/\ //'g | grep $1)
                if [ $? -eq 0 ];then
                        ACTION=$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/audit/auditd.conf | sed -e 's/\ //'g | grep $1 | awk -F '=' '{print $2}')
                        if [ "${ACTION,,}" != "rotate" ];then
                            exit 1
                        fi
                else
                        exit 1
                fi
            ;;
        admin_space_left_action)
                EXIST=$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/audit/auditd.conf | sed -e 's/\ //'g | grep $1)
                if [ $? -eq 0 ];then
                        ACTION=$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/audit/auditd.conf | sed -e 's/\ //'g | grep $1 | awk -F '=' '{print $2}')
                        if [ "${ACTION,,}" != "single" ];then
                            exit 1
                        fi
                else
                        exit 1
                fi
            ;;
        account)
                if ! auditctl -l | grep "/etc/passwd" ;then
                        exit 1
                elif ! auditctl -l | grep "/etc/shadow";then
                        exit 1
                elif ! auditctl -l | grep "/etc/group";then
                        exit 1
                elif ! auditctl -l | grep "/etc/gshadow";then
                        exit 1
                elif ! auditctl -l | grep "/etc/security/opasswd";then
                        exit 1
                fi
            ;;
        network)
                if ! auditctl -l | grep "sethostname" ;then
                        exit 1
                elif ! auditctl -l | grep "setdomainname";then
                        exit 1
                elif ! auditctl -l | grep "/etc/issue.net";then
                        exit 1
                elif ! auditctl -l | grep "/etc/hosts";then
                        exit 1
                elif ! auditctl -l | grep "/etc/sysconfig";then
                        exit 1
                elif ! auditctl -l | grep "network";then
                        exit 1
                fi
            ;;
        apparmor-config)
                if ! auditctl -l | grep "/etc/apparmor/" ;then
                        exit 1
                elif ! auditctl -l | grep "/etc/apparmor.d/";then
                        exit 1
                fi
            ;;
        failed-access-files-programs)
                if ! auditctl -l | grep "EACCES" ;then
                        exit 1
                elif ! auditctl -l | grep "EPERM";then
                        exit 1
                fi
            ;;
        setuid-setgid)
                find / -xdev -type f -perm /6000 2>/dev/null | while read line;do
                        if ! auditctl -l | grep "$line" ;then
                                exit 1
                        fi
                done
            ;;
        deletions)
                if ! auditctl -l | grep "rmdir" ;then
                        exit 1
                elif ! auditctl -l | grep "unlink";then
                        exit 1
                elif ! auditctl -l | grep "unlinkat";then
                        exit 1
                elif ! auditctl -l | grep "rename";then
                        exit 1
                elif ! auditctl -l | grep "renameat";then
                        exit 1
                fi
            ;;
        kernel-modules)
                if ! auditctl -l | egrep -e "(-w |-F path=)/sbin/insmod";then
                        exit 1
                elif ! auditctl -l | egrep -e "(-w |-F path=)/sbin/rmmod";then
                        exit 1
                elif ! auditctl -l | egrep -e "(-w |-F path=)/sbin/modprobe";then
                        exit 1
                elif ! auditctl -l | grep -w "init_module";then
                        exit 1
                elif ! auditctl -l | grep -w "delete_module";then
                        exit 1
                fi
            ;;
esac
