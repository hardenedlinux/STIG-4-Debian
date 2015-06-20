#!/bin/bash

case $1 in
        atd)
                if service --status-all | grep "+.*atd";then
                        exit 1
                fi
        ;;
        avahi-daemon)
                if service --status-all | grep "+.*avahi-daemon";then
                        exit 1
                fi
        ;;
        xinetd)
                if service --status-all | grep "+.*xinetd";then
                        exit 1
                fi
        ;;
        telnetd)
                if sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/inetd.conf | grep telnet;then
                        exit 1
                fi
        ;;
        rshd)
                if sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/inetd.conf | grep rshd;then
                        exit 1
                fi
        ;;
        rexecd)
                if sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/inetd.conf | grep rexecd;then
                        exit 1
                fi
        ;;
        rlogind)
                if sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/inetd.conf | grep rlogind;then
                        exit 1
                fi
        ;;
        nis)
                if service --status-all | grep "+.*\ nis$";then
                        exit 1
                fi
        ;;
        tftpd)
                if sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/inetd.conf | grep tftpd;then
                        exit 1
                fi
        ;;
        cron)
                if service --status-all | grep "+.*cron";then
                        exit 1
                fi
        ;;
        ntp)
                if service --status-all | grep "+.*ntp";then
                        exit 1
                fi
        ;;
esac
