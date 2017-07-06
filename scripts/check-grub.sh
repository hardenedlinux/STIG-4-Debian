#!/bin/bash

case $1 in 
	removable)
		COUNT=$(grep -v "hd0" /boot/grub/grub.cfg | grep -c "set root")

		if [ "${COUNT}" -eq 0 ];then
			:
		else
			exit 1
		fi
		;;
	password_pbkdf2)
		COUNT1=$(grep -ic "^set.*superusers=\"root\"" /boot/grub/grub.cfg)
		COUNT2=$(grep -ic "^password_pbkdf2.*root.*grub.pbkdf2.sha512.*" /boot/grub/grub.cfg)

		if [ "${COUNT1}" -lt 1 -o "${COUNT2}" -lt 1 ];then
			exit 1
		fi
	;;
	password_pbkdf2_efi)
		COUNT1=$(grep -ic "^set.*superusers=\"root\"" /boot/efi/* -r)
		COUNT2=$(grep -ic "^password_pbkdf2.*root.*grub.pbkdf2.sha512.*" /boot/efi/* -r)

		if [ "${COUNT1}" -lt 1 -o "${COUNT2}" -lt 1 ];then
			exit 1
		fi
	;;
esac


