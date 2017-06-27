#!/bin/bash

case $1 in 
	removable)
		COUNT=`grep "set root" /boot/grub/grub.cfg | grep -v "hd0" | wc -l `

		if [ ${COUNT} -eq 0 ];then
			:
		else
			exit 1
		fi
		;;
	password_pbkdf2)
		COUNT1=`grep -i "^set.*superusers=\"root\"" /boot/grub/grub.cfg | wc -l`
		COUNT2=`grep -i "^password_pbkdf2.*root.*grub.pbkdf2.sha512.*" /boot/grub/grub.cfg | wc -l`

		if [ ${COUNT1} -lt 1 -o ${COUNT2} -lt 1 ];then
			exit 1
		fi
	;;
	password_pbkdf2_efi)
		COUNT1=`grep -i "^set.*superusers=\"root\"" /boot/efi/* -r | wc -l`
		COUNT2=`grep -i "^password_pbkdf2.*root.*grub.pbkdf2.sha512.*" /boot/efi/* -r | wc -l`

		if [ ${COUNT1} -lt 1 -o ${COUNT2} -lt 1 ];then
			exit 1
		fi
	;;
esac


