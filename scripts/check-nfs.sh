#!/bin/bash

if mount | grep ".*type.*nfs";then
        COUNT1=`mount | grep ".*type.*nfs" | wc -l`
        COUNT2=`mount | grep ".*type.*nfs" | grep noexec | wc -l`
        if [ ${COUNT1} -ne ${COUNT2} ];then
                exit 1
        fi
fi
