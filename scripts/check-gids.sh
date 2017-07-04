#!/bin/bash

if [ "$(pwck -r | grep -c "no group")" -ne 0 ];then
        exit 1
fi
