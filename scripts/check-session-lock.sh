#!/bin/bash

session_lock=`gsettings get org.gnome.desktop.screensaver lock-enabled`

if [ "${session_lock}"="true" ]; then
	:
else
	exit 1
fi
