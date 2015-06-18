#!/bin/bash

HOSTS="/etc/hosts.equiv"

if [ -f "$HOSTS" ];then
        echo "Found hosts.equiv"
        exit 1
else
        echo "hosts.equiv no found"
fi
if [ -f ~/.rhosts ];then
        echo "Found .rhosts in /root"
        exit 1
else
        echo ".rhosts no found in /root"
fi
for i in $(awk -F':' '{ if ( $3 >= 500 ) print $1 }' /etc/passwd);do
        HOMEDIR=`eval "echo ~$i"`
        if [ -f "$HOMEDIR/.rhosts" ];then
                echo "Found .rhosts in $HOMEDIR"
                exit 1
        else
                echo ".rhosts no found in $HOMEDIR"
        fi
done
