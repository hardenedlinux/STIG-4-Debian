#!/bin/bash
FIPS="aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc"
cipher=$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/ssh/sshd_config | grep -i "Ciphers")
if [ $? -eq 0 ];then
        echo $cipher | sed -e 's/Ciphers//' | tr "," "\n" | while read line;do
                 if ! echo $FIPS | grep $line;then
                         exit 1
                 fi
        done
else
        exit 1
fi
