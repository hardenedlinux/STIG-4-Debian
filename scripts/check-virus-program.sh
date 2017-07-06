#!/bin/bash

case $1 in
	virus-scan-program)
		if systemctl status clamav-freshclam | grep "Active:.*(running)";then
			:
		else
			exit 1  
		fi
	;;
	virus-update)
		NOWTIME=`date +"%s"`
		VIRUSTIME=`stat -c "%Y" /var/lib/clamav/daily.cld`

		INTERVALTIME=$((${NOWTIME}-${VIRUSTIME})) 
		echo ${INTERVALTIME}

		if [ "${INTERVALTIME}" -ge 604800 ];then
			exit 1
		fi
	;;
esac

