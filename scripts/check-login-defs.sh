#!/bin/bash

LOCATION=$1
KEYWORD=$2
OPTION=$3

if [ -f "$LOCATION" ];then

        RESULT=$(sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' $LOCATION | grep "$KEYWORD.*$OPTION")
        #above line is remove any comment in the configuration file and use grep to output a exit status
        #if matched both $KEYWORD and $OPTION there is a success exit status: 0

        if [ $? -eq 0 ];then
                if [ "$(echo $RESULT | tr "\t" "\n" | tr " " "\n" | sed -n "/$OPTION/p"| awk -F "=" '{printf $2}')" -$(echo $COMPARE) "$CONDITION" ];then
                        exit 1
                fi
        else
                exit 1
        fi 

fi
