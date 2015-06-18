#!/bin/bash
#In STIG there is only 5 kinds of permission : 0000, 0644, 0755, 0600, 0640
LOCALTION=$1
PERM=$2

LEN=(stat $LOCALTION -c %a) 
#if permisiion of the file or directory 


if [ $LEN == 4 ];then
       exit 1
fi

let FPERM=777-$PERM

find $LOCALTION -perm /$(printf "%03d\n" $FPERM) | wc -l | awk -F: '($1 != "0") {print; err=1} END {exit err}'
