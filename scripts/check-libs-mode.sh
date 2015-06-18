#!/bin/bash

if [ -d "/lib" ];then

        COUNT=$(find -L /lib  -type f  -perm  /022  -exec ls -l {} \; |wc -l)

        if [ $COUNT -eq 0 ];then
                :
        else
                exit 1
        fi
fi
if [ -d "/lib64" ];then

        COUNT=$(find -L /lib64  -type f  -perm  /022  -exec ls -l {} \; |wc -l)

        if [ $COUNT -eq 0 ];then
                :
        else
                exit 1
        fi
fi
if [ -d "/usr/lib" ];then

        COUNT=$(find -L /usr/lib  -type f  -perm  /022  -exec ls -l {} \; |wc -l)

        if [ $COUNT -eq 0 ];then
                :
        else
                exit 1
        fi
fi
if [ -d "/usr/lib64" ];then

        COUNT=$(find -L /usr/lib64  -type f  -perm  /022  -exec ls -l {} \; |wc -l)

        if [ $COUNT -eq 0 ];then
                :
        else
                exit 1
        fi
fi
