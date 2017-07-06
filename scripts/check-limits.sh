#!/bin/bash
case $1 in
        core-dumps)
                if sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/security/limits.conf | grep "hard.*core";then
                        if [ "$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/security/limits.conf | grep "hard.*core" | awk -F 'core' '{print $2}' | sed 's/\ *//g')" -ne 0 ];then
                                exit 1
                        fi
                else
                        exit 1
                fi
        ;;
        maxlogins)
                if sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/security/limits.conf | grep "maxlogins";then
                        if [ "$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/security/limits.conf | grep "maxlogins" | awk -F 'maxlogins' '{print $2}' | sed 's/\ *//g')" -lt 10 ];then
                                exit 1
                        fi
                else
                        exit 1
                fi
        ;;
esac
