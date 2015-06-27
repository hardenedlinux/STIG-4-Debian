#!/bin/bash

if grep -r bluetooth /etc/modprobe.d;then
        if ! grep -r net-pf-31 /etc/modprobe.d;then
                exit 1
        fi
else
        exit 1
fi
