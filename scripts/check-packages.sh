#!/bin/bash

case $1 in
        xinetd)
                if dpkg -s xinetd ;then
                        exit 1
                fi
        ;;
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
        nis)
                if dpkg -s nis ;then
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
        sldap)
                if dpkg -s sldap ;then
                        exit 1
                fi
        ;;
        sendmail)
                if dpkg -s sendmail ;then
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
