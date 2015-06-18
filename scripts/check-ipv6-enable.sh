#!/bin/bash

if [ -a /proc/net/if_inet6 ];then
        echo bad
        exit 1
fi
