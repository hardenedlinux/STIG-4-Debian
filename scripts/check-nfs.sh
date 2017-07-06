#!/bin/bash

if mount | grep ".*type.*nfs";then
        COUNT1=`mount | grep -c ".*type.*nfs"`
        COUNT2=`mount | grep ".*type.*nfs" | grep -c noexec`
        if [ "${COUNT1}" -ne "${COUNT2}" ];then
                exit 1
        fi
fi
