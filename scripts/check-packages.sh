#!/bin/bash

case $1 in
        telnetd)
                if dpkg -s telnetd ;then
                        exit 1
                fi
        ;;
        rsh-server)
                if dpkg -s rsh-server ;then
                        exit 1
                fi
        ;;
	vsftpd)
		if dpkg -s vsftpd ;then
                        exit 1
                fi
        ;;
        tftpd)
                if dpkg -s tftpd ;then
                        exit 1
                fi
        ;;
        x11-common)
                if dpkg -s x11-common ;then
                        exit 1
                fi
        ;;
        ypserv)
                if dpkg -s ypserv ;then
                        exit 1
                fi
        ;;
esac
