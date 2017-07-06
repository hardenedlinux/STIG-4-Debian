#!/bin/bash

SESSION_LOCK=`gsettings get org.gnome.desktop.screensaver lock-enabled`

if [ "${SESSION_LOCK}" = "true" ]; then
	:
else
	exit 1
fi
