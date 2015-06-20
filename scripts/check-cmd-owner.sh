#!/bin/bash

if [ -d "/bin" ];then

        COUNT=$(find -L /bin  \! -user root  -exec ls -l {} \; |wc -l)

        if [ $COUNT -eq 0 ];then
                :
        else
                exit 1
        fi
fi
if [ -d "/usr/bin" ];then

        COUNT=$(find -L /usr/bin  \! -user root  -exec ls -l {} \; |wc -l)

        if [ $COUNT -eq 0 ];then
                :
        else
                exit 1
        fi
fi
if [ -d "/usr/local/bin" ];then

        COUNT=$(find -L /usr/local/bin  \! -user root  -exec ls -l {} \; |wc -l)

        if [ $COUNT -eq 0 ];then
                :
        else
                exit 1
        fi
fi
if [ -d "/sbin" ];then

        COUNT=$(find -L /sbin  \! -user root  -exec ls -l {} \; |wc -l)

        if [ $COUNT -eq 0 ];then
                :
        else
                exit 1
        fi
fi
if [ -d "/usr/sbin" ];then

        COUNT=$(find -L /usr/sbin  \! -user root  -exec ls -l {} \; |wc -l)

        if [ $COUNT -eq 0 ];then
                :
        else
                exit 1
        fi
fi
if [ -d "/usr/local/sbin" ];then

        COUNT=$(find -L /usr/local/sbin  \! -user root  -exec ls -l {} \; |wc -l)

        if [ $COUNT -eq 0 ];then
                :
        else
                exit 1
        fi
fi
