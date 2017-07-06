#!/bin/bash

for line in $(egrep ":[0-9]{4}:" /etc/passwd | cut -d: -f6)
do
	if [ ! -e "${line}" ];then
		exit 1
	else	
		# if umask not set, return error
		UMASK_IS_SET=`grep -d skip -i umask /home/*/.* | grep -v ":#" | grep -v ".viminfo" | grep -v ".bash_history" | wc -l`
		if [ "${UMASK_IS_SET}" -eq 0 ];then
			exit 1
		else
			# umask set is to mode 700 or less permissive.
			COUNT=`grep -d skip -i umask /home/*/.* | grep -v ":#" | grep -v ".viminfo" | grep -v ".bash_history" | grep -v ".77" | wc -l`
			if [ "${COUNT}" -eq 0 ];then
				:
			else
				exit 1
			fi
		fi
	fi
done

