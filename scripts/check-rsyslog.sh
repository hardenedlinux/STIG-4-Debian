#!/bin/bash

case "$1" in

        owned)
                if [ "$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/rsyslog.conf | grep FileOwner | awk '{print $2}')" != "root" ];then
                        exit 1
                fi
                sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/rsyslog.conf | sed  -e '/\$/d' | awk '{print $2}' | sed -e '/^:/d' -e '/|/d' -e 's/^-//g' -e '/^$/d' | \
                while read line;do
                        if [ -f $line ] && [ "$(ls -alh $line | awk '{print $3}')" != "root" ];then
                                        exit 1
                        fi
                done
        ;;
        group-owned)
                if [ "$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/rsyslog.conf | grep FileGroup | awk '{print $2}')" != "root" ];then
                        exit 1
                fi
                sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/rsyslog.conf | sed  -e '/\$/d' | awk '{print $2}' | sed -e '/^:/d' -e '/|/d' -e 's/^-//g' -e '/^$/d' | \
                while read line;do
                        if [ -f $line ] && [ "$(ls -alh $line | awk '{print $4}')" != "root" ];then
                                        exit 1
                        fi
                done
        ;;
        mode)
                sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/rsyslog.conf | sed  -e '/\$/d' | awk '{print $2}' | sed -e '/^:/d' -e '/|/d' -e 's/^-//g' -e '/^$/d' | \
                while read line;do
                        bash check-mode.sh $line 600
                        if [ $? -eq 1 ];then
                                exit 1
                        fi
                done

        ;;
esac
