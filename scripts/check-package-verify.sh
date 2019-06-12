#!/bin/bash

if [ $(dpkg --verify | grep "^..5" | awk '$2 != "c" { print $NF }' | xargs -I XXX bash -c "[ -f \"XXX\" ] && echo \"XXX\"" | wc -l) -gt 0 ];then
	exit 1
fi

