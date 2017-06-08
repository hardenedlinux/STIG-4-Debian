#!/bin/bash

idle_delay=`gsettings get org.gnome.desktop.session idle-delay | awk '{print $2}'`

if [ "${idle_delay}" -le 900 ]; then
	:
else
	exit 1
fi
