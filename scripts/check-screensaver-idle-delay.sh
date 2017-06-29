#!/bin/bash

IDLE_DELAY=`gsettings get org.gnome.desktop.session idle-delay | awk '{print $2}'`

if [ "${IDLE_DELAY}" -le 900 ]; then
	:
else
	exit 1
fi
