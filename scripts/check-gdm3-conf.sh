#!/bin/bash

case $1 in
 	AutomaticLoginEnable)
		if [ $(grep -v "^#" /etc/gdm3/ -r | grep -i "automaticloginenable.*=.*true" | wc -l) -eq 1 ]; then
			exit 1
		fi
	;;
 	TimedLoginEnable)
		if $(grep -v "^#" /etc/gdm3/ -r | grep -i "TimedLoginEnable.*=.*true" | wc -l) -eq 1; then
			exit 1
		fi
	;;
esac

