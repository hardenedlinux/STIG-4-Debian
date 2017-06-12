#!/bin/bash

if [ $(pwck -r | grep "no group" | wc -l) -ne 0 ];then
        exit 1
fi
