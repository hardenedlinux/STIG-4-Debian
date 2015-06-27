#!/bin/bash

case $1 in
        smb-signing)
                if dpkg -s samba >/dev/null 2>&1;then
                        if ! sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' -e '/^;/d' /etc/samba/smb.conf | grep "client.*signing.*mandatory";then
                                exit 1
                        fi
                fi
        ;;
        smb-sec)
                if [ "$(grep "cifs.*sec=krb5a\|cifs.*sec=ntlmv2i" /etc/mtab /etc/fstab | wc -l)" != "$(grep "cifs" /etc/mtab /etc/fstab | wc -l)" ];then
                        exit 1
                fi
        ;;
        libuser)
                if [ -f /etc/libuser.conf ];then
                        if ! sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/libuser.conf | grep "crypt_style.*sha512";then
                                exit 1
                        fi
                fi 
        ;;
        icmpv6)
                if [ -a /proc/net/if_inet6 ];then
                        if ! sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/libuser.conf | grep "crypt_style.*sha512";then
                                exit 1
                        fi
                fi 
        ;;
esac
