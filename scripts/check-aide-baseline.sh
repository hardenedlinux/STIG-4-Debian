#!/bin/bash
#Tested on Aide 0.16a2-19-g16ed855

CHECKDATABASE=$(grep "database=" /etc/aide/aide.conf  2>/dev/null )
if [ $? -eq 0 ];then
        :
else 
        echo "couldn""'""t found aide.conf"
        exit 1
fi

DATABASE=$(echo $CHECKDATABASE | awk -F ':' '{printf $2}' 2>/dev/null)

if [ $? -eq 0 ];then
        :
else 
        echo "couldn""'""t found database location at aide.conf"
        exit 1
fi

if [ -f "$DATABASE" ];then
        echo "There is a baseline for aide."
	exit 0
else
        echo "Can""'""t find aide baseline"
	exit 1
fi
