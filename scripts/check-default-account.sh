#!/bin/bash
echo $(awk -F: '$1 !~ /^root$/ && $2 !~ /^[!*]/ {print $1 ":" $2}' /etc/shadow | awk -F ':' '{printf $1}' )| while read ACCOUNT
do      
        awk -F':' '{ if ( $3 <= 500 ) print $1 }' /etc/passwd | sed '/^root$/d' | while read ACCOUNTLIST
        do      
                if [ "$ACCOUNT" == "$ACCOUNTLIST" ];then
                        echo "There is at least one default account is using"
                        exit 1
                fi
        done
done
