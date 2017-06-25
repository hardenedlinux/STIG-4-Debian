#!/bin/bash


if systemctl status autofs | grep "Active:.*(running)";then
	exit 1  
fi

