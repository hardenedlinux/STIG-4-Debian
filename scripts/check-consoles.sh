#!/bin/bash
case $1 in
        virtual)
                if [ -f /etc/securetty ];then
                        if grep '^vc/[0-9]' /etc/securetty;then
                                exit 1
                        fi
                else
                        exit 0
                fi
        ;;
        serial)
                if [ -f "/etc/securetty" ];then
                        if grep '^ttyS[0-9]' /etc/securetty;then
                                exit 1
                        fi
                else
                        exit 0
                fi
        ;;
esac
