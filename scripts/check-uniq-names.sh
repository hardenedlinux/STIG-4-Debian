#!/bin/bash

if [ $(pwck -rq | wc -l ) -ne 0 ];then
        exit 1
fi
