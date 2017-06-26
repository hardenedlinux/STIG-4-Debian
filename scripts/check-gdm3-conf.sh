#!/bin/bash

case $1 in
 	AutomaticLoginEnable)
		if [ $(grep -v "^#" /etc/gdm3/ -r | grep -i "automaticloginenable.*=.*true" | wc -l) -eq 1 ]; then
			exit 1
		fi
	;;
 	TimedLoginEnable)
		if [ $(grep -v "^#" /etc/gdm3/ -r | grep -i "TimedLoginEnable.*=.*true" | wc -l) -eq 1 ]; then
			exit 1
		fi
	;;
 	banner-message-enable)
		if [ $(grep -v "^#" /etc/gdm3/greeter.dconf-defaults | grep -i "^banner-message-enable=true" | wc -l) -eq 0 ]; then
			exit 1
		fi
	;;
 	banner-message-text)
		if [ -z $(grep -v "^#" /etc/gdm3/greeter.dconf-defaults | grep -i "banner-message-text" | awk -F= '{print $2}') ]; then
			exit 1
		fi
	;;
esac

