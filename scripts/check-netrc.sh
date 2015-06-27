#!/bin/bash

if [ -f ~/.netrc ];then
        echo "Found .netrc in /root"
        exit 1
else
        echo ".netrc no found in /root"
fi
for i in $(awk -F':' '{ if ( $3 >= 500 ) print $1 }' /etc/passwd);do
        HOMEDIR=`eval "echo ~$i"`
        if [ -f "$HOMEDIR/.netrc" ];then
                echo "Found .netrc in $HOMEDIR"
                exit 1
        else
                echo ".netrc no found in $HOMEDIR"
        fi
done
