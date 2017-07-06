#!/bin/bash

PUBCOUNT=`grep public /etc/snmp/snmpd.conf | grep -v "^#" | wc -l`
PRICOUNT=`grep private /etc/snmp/snmpd.conf | grep -v "^#" | wc -l`

if [ "${PUBCOUNT}" -gt 0 -o "${PRICOUNT}" -gt 0 ];then
	exit 1
fi

