#!/bin/bash


VERSION='0.1'
DATE=`date +%F`
LOG=/var/log/STIG-Checking-$DATE.log
# support en(English) and cn(chinese)
SETLANG="cn"

# Script Version
function version() {
	echo "STIG For Debian (v.$VERSION)"
}

function usage() {
cat << EOF
usage: $0 [options]

  -c    Output Log with catable colors
  -s    Perform STIG checking with NORMAL output log
  -v    Show version
  -h 	Show this message

Default log file location at /var/log/STIG-Checking-*.log

STIG Check for Debian (v$VERSION)

Port DISA RHEL 6 STIG V1R7 for Debian

EOF
}


if [ $# -eq 0 ];then
        usage
	exit 1
elif [ $# -gt 1 ];then
        tput setaf 1;echo -e "\033[1mERROR: Invalid Option Provided!\033[0m";tput sgr0
	echo
        usage
	exit 1
fi

while getopts ":csvhq" OPTION; do
	case $OPTION in
	        c)      CATCOLOR=1
		        ;;
	        s)      
		        ;;
		v)
			version
			exit 0
			;;
		h)
			usage
			exit 0
			;;
		?)
			tput setaf 1;echo -e "\033[1mERROR: Invalid Option Provided!\033[0m";tput sgr0
			echo
			usage
			exit 1
			;;
	esac
done

if [[ $EUID -ne 0 ]]; then
		echo
		tput setaf 1; #Setting Output Color To Red 
		echo -e "\033[1mPlease re-run this script as root!\033[0m";
		tput sgr0 #Turn off all attributes
	exit 1
fi

# CREATE LOG IF IT DOESN'T EXISIT
if [ ! -e $LOG ]; then
	touch $LOG
fi


RUNTIME=$(date)
printf "SCRIPT RUN: $RUNTIME\nStarting Checking...\n\n" | tee $LOG

log_msg(){

        ESTATUS=$1
        RED=$(tput setaf 1)
        BOLD=$(tput bold)
        GREEN=$(tput setaf 2)
        NORMAL=$(tput sgr0)
        MSG="$2"
       
        #let COL1=$(tput cols)-${#MSG}+${#GREEN}+${#NORMAL}+${#BOLD}-4
        #let COL2=$(tput cols)-${#MSG}+${#RED}+${#NORMAL}+${#BOLD}-4
        #
       
        if [ $ESTATUS -eq 0 ];then
                #printf "%s%${COL1}s" "$MSG" "$GREEN$BOLD[ PASS ]$NORMAL"
                printf "%s %s"  "$GREEN$BOLD[ PASS ]$NORMAL" "$MSG"
                echo
                if [ -z "$CATCOLOR" ];then
                        printf "%s %s\n\n" "[ PASS ]" "$MSG" >> $LOG
                else
                        printf "%s %s\n\n" "$GREEN$BOLD[ PASS ]$NORMAL" "$MSG" >> $LOG
                fi
        else
                #printf "%s%${COL2}s" "$MSG" "$RED$BOLD[ FAIL ]$NORMAL"
                printf "%s %s"  "$RED$BOLD[ FAIL ]$NORMAL" "$MSG"
                echo
                if [ -z "$CATCOLOR" ];then
                    printf "%s %s\n\n" "[ FAIL ]" "$MSG" >> $LOG
                else
                    printf "%s %s\n\n" "$RED$BOLD[ FAIL ]$NORMAL" "$MSG" >> $LOG
                fi
        fi
}

source scripts/output.sh

spinner(){

        local pid=$1
        local delay=0.1
        local spinstr='|/-\'
        while [ "$(ps -a | awk '{print $1}' | grep "$pid")" ]; 
        do
                local temp=${spinstr#?}
                printf "%c" "$spinstr"
                local spinstr=$temp${spinstr%"$temp"}
                sleep $delay
                printf "\b"
        done
        printf " \b"
        wait $1 
}





###################################

##RHEL-06-000001
##The system must use a separate file system for /tmp.
mount | grep "on /tmp " >/dev/null 2>&1 &

spinner $!
output "V-38455" $? ${SETLANG}
################

##RHEL-06-000002
##The system must use a separate file system for /var.
mount | grep "on /var " >/dev/null 2>&1 &

spinner $!
output "V-38456" $? ${SETLANG}
################

##RHEL-06-000003
##The system must use a separate file system for /var/log.
mount | grep "on /var/log " >/dev/null 2>&1 &

spinner $!
output "V-38463" $? ${SETLANG}
################

##RHEL-06-000004
##The system must use a separate file system for the system audit data path.
mount | grep "on /var/log/audit " >/dev/null 2>&1 &

spinner $!
output "V-38467" $? ${SETLANG}
################

##RHEL-06-000005
##The audit system must alert designated staff members when the audit storage volume approaches capacity.
bash scripts/check-auditd.sh space_left_action >/dev/null 2>&1 &

spinner $!
output "V-38470" $? ${SETLANG}
################

##RHEL-06-000007
##The system must use a separate file system for user home directories.
mount | grep "on /home " >/dev/null 2>&1 &

spinner $!
output "V-38473" $? ${SETLANG}
################

##RHEL-06-000008
##Vendor-provided cryptographic certificates must be installed to verify the integrity of system software.

bash scripts/check-apt-key.sh >/dev/null 2>&1 &

spinner $!
output "V-38476" $? ${SETLANG}
################

##RHEL-06-000011
##System security patches and updates must be installed and up-to-date.

bash scripts/check-package-up2date.sh >/dev/null 2>&1 &

spinner $!
output "V-38481" $? ${SETLANG}
################

##RHEL-06-000013
##The system package management tool must cryptographically verify the authenticity of system software packages during installation.


#spinner $!
#output "V-38483" $? ${SETLANG}
################

##RHEL-06-000015
##The system package management tool must cryptographically verify the authenticity of all software packages during installation.


#spinner $!
#output "V-38487" $? ${SETLANG}
################

##RHEL-06-000016
##A file integrity tool must be installed.

dpkg -s aide >/dev/null 2>&1 &

spinner $!
output "V-38489" $? ${SETLANG}
################

##RHEL-06-000017
##The system must use a Linux Security Module at boot time.(AppArmor)

grep "apparmor=1" /boot/grub/grub.cfg >/dev/null 2>&1 &

spinner $!
output "V-51337" $? ${SETLANG}
################

##RHEL-06-000018
##A file integrity baseline must be created.
#Aide 0.16a2-19-g16ed855 

bash scripts/check-aide-baseline.sh > /dev/null 2>&1 &

spinner $!
output "V-51391" $? ${SETLANG}
################

##RHEL-06-000019
##There must be no .rhosts or hosts.equiv files on the system.

bash scripts/check-rhosts.sh > /dev/null 2>&1 &

spinner $!
output "V-38491" $? ${SETLANG}
################

##RHEL-06-000020
##The system must use a Linux Security Module configured to enforce limits on system services.


#spinner $!
#output "V-51363" $? ${SETLANG}
################

##RHEL-06-000023
##The system must use a Linux Security Module configured to limit the privileges of system services.


#spinner $!
#output "V-51369" $? ${SETLANG}
################

##RHEL-06-000025
##All device files must be monitored by the system Linux Security Module.


#spinner $!
#output "V-51379" $? ${SETLANG}
################

##RHEL-06-000027
##The system must prevent the root account from logging in from virtual consoles.

bash scripts/check-consoles.sh virtual > /dev/null  2>&1 &

spinner $!
output "V-38492" $? ${SETLANG}
################

##RHEL-06-000028
##The system must prevent the root account from logging in from serial consoles.

bash scripts/check-consoles.sh serial > /dev/null  2>&1 &

spinner $!
output "V-38494" $? ${SETLANG}
################

##RHEL-06-000029
##Default operating system accounts, other than root, must be locked.

bash scripts/check-default-account.sh > /dev/null 2>&1 &

spinner $!
output "V-38496" $? ${SETLANG}
################

##RHEL-06-000030
##The system must not have accounts configured with blank or null passwords.
##For more Detial http://www.cyberciti.biz/tips/how-to-linux-prevent-the-reuse-of-old-passwords.html
##For more Detial http://www.cyberciti.biz/tips/linux-or-unix-disable-null-passwords.html

grep nullok /etc/pam.d/common-password > /dev/null 2>&1 &

spinner $!
output "V-38497" $? ${SETLANG}
################

##RHEL-06-000031
##The /etc/passwd file must not contain password hashes.

awk -F: '($2 != "x") {print; err=1} END {exit err}' /etc/passwd > /dev/null 2>&1 &

spinner $!
output "V-38499" $? ${SETLANG}
################

##RHEL-06-000032
##The root account must be the only account having a UID of 0.

bash scripts/check-root-uid.sh > /dev/null 2>&1 &

spinner $!
output "V-38500" $? ${SETLANG}
################

##RHEL-06-000033
##The /etc/shadow file must be owned by root.

ls -l /etc/shadow | awk '{print $3}' | grep "^root$" > /dev/null 2>&1 &

spinner $!
output "V-38502" $? ${SETLANG}
################

##RHEL-06-000034
##The /etc/shadow file must be group-owned by root.

ls -l /etc/shadow | awk '{print $4}' | grep "^root$" > /dev/null 2>&1 &

spinner $!
output "V-38503" $? ${SETLANG}
################

##RHEL-06-000035
##The /etc/shadow file must have mode 0000.

ls -l /etc/shadow | awk '{print $1}' | grep "^----------$" > /dev/null 2>&1 &

spinner $!
output "V-38504" $? ${SETLANG}
################

##RHEL-06-000036
##The /etc/gshadow file must be owned by root.

ls -l /etc/gshadow | awk '{print $3}' | grep "^root$" > /dev/null 2>&1 &

spinner $!
output "V-38443" $? ${SETLANG}
################

##RHEL-06-000037
##The /etc/gshadow file must be group-owned by root.

ls -l /etc/gshadow | awk '{print $4}' | grep "^root$" > /dev/null 2>&1 &

spinner $!
output "V-38448" $? ${SETLANG}
################

##RHEL-06-000038
##The /etc/gshadow file must have mode 0000.

ls -l /etc/gshadow | awk '{print $1}' | grep "^----------$" > /dev/null 2>&1 &

spinner $!
output "V-38449" $? ${SETLANG}
################

##RHEL-06-000039
##The /etc/passwd file must be owned by root.

ls -l /etc/passwd | awk '{print $3}' | grep "^root$" > /dev/null 2>&1 &

spinner $!
output "V-38450" $? ${SETLANG}
################

##RHEL-06-000040
##The /etc/passwd file must be group-owned by root.

ls -l /etc/passwd | awk '{print $4}' | grep "^root$" > /dev/null 2>&1 &

spinner $!
output "V-38451" $? ${SETLANG}
################

##RHEL-06-000041
##The /etc/passwd file must have mode 0644 or less permissive.

bash scripts/check-mode.sh /etc/passwd 644 > /dev/null 2>&1 &

spinner $!
output "V-38457" $? ${SETLANG}
################

##RHEL-06-000042
##The /etc/group file must be owned by root.

ls -l /etc/group | awk '{print $3}' | grep "^root$" > /dev/null 2>&1 &

spinner $!
output "V-38458" $? ${SETLANG}
################

##RHEL-06-000043
##The /etc/group file must be group-owned by root.

ls -l /etc/group | awk '{print $4}' | grep "^root$" > /dev/null 2>&1 &

spinner $!
output "V-38459" $? ${SETLANG}
################

##RHEL-06-000044
##The /etc/group file must have mode 0644 or less permissive.

bash scripts/check-mode.sh "/etc/group" 644 > /dev/null 2>&1 &

spinner $!
output "V-38461" $? ${SETLANG}
################

##RHEL-06-000045
##Library files must have mode 0755 or less permissive.

bash scripts/check-libs-mode.sh > /dev/null 2>&1 &

spinner $!
output "V-38465" $? ${SETLANG}
################

##RHEL-06-000046
##Library files must be owned by root.

bash scripts/check-libs-owner.sh > /dev/null 2>&1 &

spinner $!
output "V-38466" $? ${SETLANG}
################

##RHEL-06-000047
##All system command files must have mode 755 or less permissive.

bash scripts/check-cmd-mode.sh > /dev/null 2>&1 &

spinner $!
output "V-38469" $? ${SETLANG}
################

##RHEL-06-000048
##All system command files must be owned by root.

bash scripts/check-cmd-owner.sh > /dev/null 2>&1 &

spinner $!
output "V-38472" $? ${SETLANG}
################

##RHEL-06-000050
##The system must require passwords to contain a minimum of 14 characters.

bash scripts/check-password-min-len.sh > /dev/null 2>&1 &

spinner $!
output "V-38475" $? ${SETLANG}
################

##RHEL-06-000051
##Users must not be able to change passwords more than once every 24 hours.

bash scripts/check-password-min-day.sh > /dev/null 2>&1 &

spinner $!
output "V-38477" $? ${SETLANG}
################

##RHEL-06-000053
##User passwords must be changed at least every 60 days.

bash scripts/check-password-max-day.sh > /dev/null 2>&1 &

spinner $!
output "V-38479" $? ${SETLANG}
################

##RHEL-06-000054
##Users must be warned 7 days in advance of password expiration.

bash scripts/check-password-warn-age.sh > /dev/null 2>&1 &

spinner $!
output "V-38480" $? ${SETLANG}
################

##RHEL-06-000056
##The system must require passwords to contain at least one numeric character.

bash scripts/check-password.sh /etc/pam.d/common-password pam_cracklib.so dcredit gt -1 > /dev/null 2>&1 &

spinner $!
output "V-38482" $? ${SETLANG}
################

##RHEL-06-000057
##The system must require passwords to contain at least one uppercase alphabetic character.

bash scripts/check-password.sh /etc/pam.d/common-password pam_cracklib.so ucredit gt -1 > /dev/null 2>&1 &

spinner $!
output "V-38569" $? ${SETLANG}
################

##RHEL-06-000058
##The system must require passwords to contain at least one special character.

bash scripts/check-password.sh /etc/pam.d/common-password pam_cracklib.so ocredit gt -1 > /dev/null 2>&1 &

spinner $!
output "V-38570" $? ${SETLANG}
################

##RHEL-06-000059
##The system must require passwords to contain at least one lowercase alphabetic character.

bash scripts/check-password.sh /etc/pam.d/common-password pam_cracklib.so lcredit gt -1 > /dev/null 2>&1 &

spinner $!
output "V-38571" $? ${SETLANG}
################

##RHEL-06-000060
##The system must require at least four characters be changed between the old and new passwords during a password change.

bash scripts/check-password.sh /etc/pam.d/common-password pam_cracklib.so difok lt 4 > /dev/null 2>&1 &

spinner $!
output "V-38572" $? ${SETLANG}
################

##RHEL-06-000061
##The system must disable accounts after three consecutive unsuccessful logon attempts.

bash scripts/check-password.sh /etc/pam.d/common-auth pam_tally deny gt 3 > /dev/null 2>&1 &

spinner $!
output "V-38573" $? ${SETLANG}
################

##RHEL-06-000062
##The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (system-auth).

sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/pam.d/* | grep password | grep pam_unix.so | grep sha512 > /dev/null 2>&1 &

spinner $!
output "V-38574" $? ${SETLANG}
################

##RHEL-06-000063
##The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (login.defs).

sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/login.defs | grep "ENCRYPT_METHOD.*SHA512" > /dev/null 2>&1 &

spinner $!
output "V-38576" $? ${SETLANG}
################

##RHEL-06-000064
##The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (libuser.conf).

bash scripts/check-depends.sh > /dev/null 2>&1 &

spinner $!
output "V-38577" $? ${SETLANG}
################

##RHEL-06-000065
##The system boot loader configuration file(s) must be owned by root.

ls -l /boot/grub/grub.cfg | awk '{print $3}' | grep "^root$" > /dev/null 2>&1 &

spinner $!
output "V-38579" $? ${SETLANG}
################

##RHEL-06-000066
##The system boot loader configuration file(s) must be group-owned by root.

ls -l /boot/grub/grub.cfg | awk '{print $4}' | grep "^root$" > /dev/null 2>&1 &

spinner $!
output "V-38581" $? ${SETLANG}
################

##RHEL-06-000067
##The system boot loader configuration file(s) must have mode 0600 or less permissive.

bash scripts/check-grub-mode.sh > /dev/null 2>&1 &

spinner $!
output "V-38583" $? ${SETLANG}
################

##RHEL-06-000068
##The system boot loader must require authentication.

sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /boot/grub/grub.cfg | grep "password.*sha512" > /dev/null 2>&1 &

spinner $!
output "V-38585" $? ${SETLANG}
################

##RHEL-06-000071
##The system must allow locking of the console screen in text mode.

dpkg -s screen >/dev/null 2>&1 &

spinner $!
output "V-38590" $? ${SETLANG}
################

##RHEL-06-000078
##The system must implement virtual address space randomization.

bash scripts/check-sysctl.sh kernel.randomize_va_space ne 2 >/dev/null 2>&1 &

spinner $!
output "V-38596" $? ${SETLANG}
################

##RHEL-06-000080
##The system must not send ICMPv4 redirects by default.

bash scripts/check-sysctl.sh net.ipv4.conf.default.send_redirects ne 0 >/dev/null 2>&1 &

spinner $!
output "V-38600" $? ${SETLANG}
################

##RHEL-06-000081
##The system must not send ICMPv4 redirects from any interface.

bash scripts/check-sysctl.sh net.ipv4.conf.all.send_redirects  ne 0 >/dev/null 2>&1 &

spinner $!
output "V-38601" $? ${SETLANG}
################

##RHEL-06-000082
##IP forwarding for IPv4 must not be enabled, unless the system is a router.

bash scripts/check-sysctl.sh net.ipv4.ip_forward  ne 0 >/dev/null 2>&1 &

spinner $!
output "V-38511" $? ${SETLANG}
################

##RHEL-06-000083
##The system must not accept IPv4 source-routed packets on any interface.

bash scripts/check-sysctl.sh net.ipv4.conf.all.accept_source_route ne 0 >/dev/null 2>&1 &

spinner $!
output "V-38523" $? ${SETLANG}
################

##RHEL-06-000084
##The system must not accept ICMPv4 redirect packets on any interface.

bash scripts/check-sysctl.sh net.ipv4.conf.all.accept_redirects ne 0 >/dev/null 2>&1 &

spinner $!
output "V-38524" $? ${SETLANG}
################

##RHEL-06-000086
##The system must not accept ICMPv4 secure redirect packets on any interface.

bash scripts/check-sysctl.sh net.ipv4.conf.all.secure_redirects ne 0 >/dev/null 2>&1 &

spinner $!
output "V-38526" $? ${SETLANG}
################

##RHEL-06-000088
##The system must log Martian packets.

bash scripts/check-sysctl.sh  net.ipv4.conf.all.log_martians ne 1 >/dev/null 2>&1 &

spinner $!
output "V-38528" $? ${SETLANG}
################

##RHEL-06-000089
##The system must not accept IPv4 source-routed packets by default.

bash scripts/check-sysctl.sh  net.ipv4.conf.default.accept_source_route ne 0 >/dev/null 2>&1 &

spinner $!
output "V-38529" $? ${SETLANG}
################

##RHEL-06-000090
##The system must not accept ICMPv4 secure redirect packets by default.

bash scripts/check-sysctl.sh  net.ipv4.conf.default.secure_redirects ne 0 >/dev/null 2>&1 &

spinner $!
output "V-38532" $? ${SETLANG}
################

##RHEL-06-000091
##The system must ignore ICMPv4 redirect messages by default.

bash scripts/check-sysctl.sh  net.ipv4.conf.default.accept_redirects ne 0 >/dev/null 2>&1 &

spinner $!
output "V-38533" $? ${SETLANG}
################

##RHEL-06-000092
##The system must not respond to ICMPv4 sent to a broadcast address.

bash scripts/check-sysctl.sh  net.ipv4.icmp_echo_ignore_broadcasts ne 1 >/dev/null 2>&1 &

spinner $!
output "V-38535" $? ${SETLANG}
################

##RHEL-06-000093
##The system must ignore ICMPv4 bogus error responses.

bash scripts/check-sysctl.sh  net.ipv4.icmp_ignore_bogus_error_responses ne 1 >/dev/null 2>&1 &

spinner $!
output "V-38537" $? ${SETLANG}
################

##RHEL-06-000095
##The system must be configured to use TCP syncookies when experiencing a TCP SYN flood.

bash scripts/check-sysctl.sh  net.ipv4.tcp_syncookies ne 1 >/dev/null 2>&1 &

spinner $!
output "V-38539" $? ${SETLANG}
################

##RHEL-06-000096
##The system must use a reverse-path filter for IPv4 network traffic when possible on all interfaces.

bash scripts/check-sysctl.sh  net.ipv4.conf.all.rp_filter ne 1 >/dev/null 2>&1 &

spinner $!
output "V-38542" $? ${SETLANG}
################

##RHEL-06-000097
##The system must use a reverse-path filter for IPv4 network traffic when possible by default.

bash scripts/check-sysctl.sh  net.ipv4.conf.default.rp_filter ne 1 >/dev/null 2>&1 &

spinner $!
output "V-38544" $? ${SETLANG}
################

##RHEL-06-000098
##The IPv6 protocol handler must not be bound to the network stack unless needed.

bash scripts/check-ipv6-enable.sh >/dev/null 2>&1 &

spinner $!
output "V-38546" $? ${SETLANG}
################

##RHEL-06-000099
##The system must ignore ICMPv6 redirects by default.
##If IPv6 is disabled, this is not applicable.

if [ -a /proc/net/if_inet6 ];then

bash scripts/check-sysctl.sh  net.ipv6.conf.default.accept_redirects ne 0 >/dev/null 2>&1 &

spinner $!
output "V-38548" $? ${SETLANG}
fi
################

##RHEL-06-000120
##The systems local IPv4 firewall must implement a deny-all, allow-by-exception policy for inbound

iptables -L INPUT | head -n1 | grep "INPUT.*DROP" >/dev/null 2>&1 &

spinner $!
output "V-38513" $? ${SETLANG}
################

##RHEL-06-000124
##The systems local IPv4 firewall must implement a deny-all, allow-by-exception policy for inbound

grep -r dccp /etc/modprobe.conf /etc/modprobe.d >/dev/null 2>&1 &

spinner $!
output "V-38514" $? ${SETLANG}
################

##RHEL-06-000125
##The Stream Control Transmission Protocol (SCTP) must be disabled unless required.

grep -r sctp /etc/modprobe.conf /etc/modprobe.d >/dev/null 2>&1 &

spinner $!
output "V-38515" $? ${SETLANG}
################

##RHEL-06-000126
##The Reliable Datagram Sockets (RDS) protocol must be disabled unless required.

grep -r rds /etc/modprobe.conf /etc/modprobe.d >/dev/null 2>&1 &

spinner $!
output "V-38516" $? ${SETLANG}
################

##RHEL-06-000127
##The Transparent Inter-Process Communication (TIPC) protocol must be disabled unless required.

grep -r tipc /etc/modprobe.conf /etc/modprobe.d >/dev/null 2>&1 &

spinner $!
output "V-38517" $? ${SETLANG}
################

##RHEL-06-000133
##All rsyslog-generated log files must be owned by root.

bash scripts/check-rsyslog.sh owned >/dev/null 2>&1 &

spinner $!
output "V-38518" $? ${SETLANG}
################

##RHEL-06-000134
##All rsyslog-generated log files must be group-owned by root.

bash scripts/check-rsyslog.sh group-owned >/dev/null 2>&1 &

spinner $!
output "V-38519" $? ${SETLANG}
################

##RHEL-06-000135
##All rsyslog-generated log files must have mode 0600 or less permissive.

bash scripts/check-rsyslog.sh mode >/dev/null 2>&1 &

spinner $!
output "V-38623" $? ${SETLANG}
################

##RHEL-06-000136
##The operating system must back up audit records on an organization defined frequency onto a different system or media than the system being audited.

sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/rsyslog.conf | grep "\..*@.*:" >/dev/null 2>&1 &

spinner $!
output "V-38520" $? ${SETLANG}
################

##RHEL-06-000137
##The operating system must support the requirement to centrally manage the content of audit records generated by organization defined information system components.

sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/rsyslog.conf | grep "\..*@.*:" >/dev/null 2>&1 &

spinner $!
output "V-38521" $? ${SETLANG}
################

##RHEL-06-000138
##System logs must be rotated daily.

bash scripts/check-logrotate.sh >/dev/null 2>&1 &

spinner $!
output "V-38624" $? ${SETLANG}
################

##RHEL-06-000145
##The operating system must produce audit records containing sufficient information to establish the identity of any user/subject associated with the event.

service auditd status >/dev/null 2>&1 &

spinner $!
output "V-38628" $? ${SETLANG}
################

##RHEL-06-000148
##The operating system must employ automated mechanisms to facilitate the monitoring and control of remote access methods.

service auditd status >/dev/null 2>&1 &

spinner $!
output "V-38631" $? ${SETLANG}
################

##RHEL-06-000154
##The operating system must produce audit records containing sufficient information to establish what type of events occurred.

service auditd status >/dev/null 2>&1 &

spinner $!
output "V-38632" $? ${SETLANG}
################

##RHEL-06-000159
##The system must retain enough rotated audit logs to cover the required log retention period.

bash scripts/check-auditd.sh num_logs lt 5 >/dev/null 2>&1 &

spinner $!
output "V-38636" $? ${SETLANG}
################

##RHEL-06-000160
##The system must set a maximum audit log file size.

bash scripts/check-auditd.sh max_log_file lt 6 >/dev/null 2>&1 &

spinner $!
output "V-38633" $? ${SETLANG}
################

##RHEL-06-000161
##The system must rotate audit log files that reach the maximum file size.

bash scripts/check-auditd.sh max_log_file_action >/dev/null 2>&1 &

spinner $!
output "V-38633" $? ${SETLANG}
################

##RHEL-06-000163
##The audit system must switch the system to single-user mode when available audit storage volume becomes dangerously low.

bash scripts/check-auditd.sh admin_space_left_action >/dev/null 2>&1 &

spinner $!
output "V-54381" $? ${SETLANG}
################

##RHEL-06-000165
##The audit system must be configured to audit all attempts to alter system time through adjtimex.

grep -w "adjtimex" /etc/audit/audit.rules >/dev/null 2>&1 &

spinner $!
output "V-38635" $? ${SETLANG}
################

##RHEL-06-000167
##The audit system must be configured to audit all attempts to alter system time through settimeofday.

grep -w "settimeofday" /etc/audit/audit.rules >/dev/null 2>&1 &

spinner $!
output "V-38522" $? ${SETLANG}
################

##RHEL-06-000169
##The audit system must be configured to audit all attempts to alter system time through stime.
##32-bit system only
if [ "$(uname -m)" = "i686" ];then
grep -w "stime" /etc/audit/audit.rules >/dev/null 2>&1 &
fi
spinner $!
output "V-38525" $? ${SETLANG}
################

##RHEL-06-000171
##The audit system must be configured to audit all attempts to alter system time through clock_settime.

grep -w "clock_settime" /etc/audit/audit.rules >/dev/null 2>&1 &

spinner $!
output "V-38527" $? ${SETLANG}
################

##RHEL-06-000173
##The audit system must be configured to audit all attempts to alter system time through /etc/localtime.

auditctl -l | grep "watch=/etc/localtime" >/dev/null 2>&1 &

spinner $!
output "V-38530" $? ${SETLANG}
################

##RHEL-06-000174
##The operating system must automatically audit account creation.

bash scripts/check-auditd.sh account >/dev/null 2>&1 &

spinner $!
output "V-38531" $? ${SETLANG}
################

##RHEL-06-000175
##The operating system must automatically audit account modification.

bash scripts/check-auditd.sh account >/dev/null 2>&1 &

spinner $!
output "V-38534" $? ${SETLANG}
################

##RHEL-06-000176
##The operating system must automatically audit account disabling actions.

bash scripts/check-auditd.sh account >/dev/null 2>&1 &

spinner $!
output "V-38536" $? ${SETLANG}
################

##RHEL-06-000177
##The operating system must automatically audit account termination.

bash scripts/check-auditd.sh account >/dev/null 2>&1 &

spinner $!
output "V-38538" $? ${SETLANG}
################

##RHEL-06-000182
##The audit system must be configured to audit modifications to the systems network configuration.

bash scripts/check-auditd.sh network >/dev/null 2>&1 &

spinner $!
output "V-38540" $? ${SETLANG}
################

##RHEL-06-000183
##The audit system must be configured to audit modifications to the systems Mandatory Access Control (MAC) configuration (Apparmor).

bash scripts/check-auditd.sh apparmor-config >/dev/null 2>&1 &

spinner $!
output "V-38541" $? ${SETLANG}
################

##RHEL-06-000184
##The audit system must be configured to audit all discretionary access control permission modifications using chmod.

grep -w "chmod" /etc/audit/audit.rules >/dev/null 2>&1 &

spinner $!
output "V-38543" $? ${SETLANG}
################

##RHEL-06-000185
##The audit system must be configured to audit all discretionary access control permission modifications using chown.

grep -w "chown" /etc/audit/audit.rules >/dev/null 2>&1 &

spinner $!
output "V-38545" $? ${SETLANG}
################

##RHEL-06-000186
##The audit system must be configured to audit all discretionary access control permission modifications using fchmod.

grep -w "fchmod" /etc/audit/audit.rules >/dev/null 2>&1 &

spinner $!
output "V-38547" $? ${SETLANG}
################

##RHEL-06-000187
##The audit system must be configured to audit all discretionary access control permission modifications using fchmodat.

grep -w "fchmodat" /etc/audit/audit.rules >/dev/null 2>&1 &

spinner $!
output "V-38550" $? ${SETLANG}
################

##RHEL-06-000188
##The audit system must be configured to audit all discretionary access control permission modifications using fchown.

grep -w "fchown" /etc/audit/audit.rules >/dev/null 2>&1 &

spinner $!
output "V-38552" $? ${SETLANG}
################

##RHEL-06-000189
##The audit system must be configured to audit all discretionary access control permission modifications using fchownat.

grep -w "fchownat" /etc/audit/audit.rules >/dev/null 2>&1 &

spinner $!
output "V-38554" $? ${SETLANG}
################

##RHEL-06-000190
##The audit system must be configured to audit all discretionary access control permission modifications using fremovexattr.

grep -w "fremovexattr" /etc/audit/audit.rules >/dev/null 2>&1 &

spinner $!
output "V-38556" $? ${SETLANG}
################

##RHEL-06-000191
##The audit system must be configured to audit all discretionary access control permission modifications using fsetxattr.

grep -w "fsetxattr" /etc/audit/audit.rules >/dev/null 2>&1 &

spinner $!
output "V-38557" $? ${SETLANG}
################

##RHEL-06-000192
##The audit system must be configured to audit all discretionary access control permission modifications using lchown.

grep -w "lchown" /etc/audit/audit.rules >/dev/null 2>&1 &

spinner $!
output "V-38558" $? ${SETLANG}
################

##RHEL-06-000193
##The audit system must be configured to audit all discretionary access control permission modifications using lremovexattr.

grep -w "lremovexattr" /etc/audit/audit.rules >/dev/null 2>&1 &

spinner $!
output "V-38559" $? ${SETLANG}
################

##RHEL-06-000194
##The audit system must be configured to audit all discretionary access control permission modifications using lsetxattr.

grep -w "lsetxattr" /etc/audit/audit.rules >/dev/null 2>&1 &

spinner $!
output "V-38561" $? ${SETLANG}
################

##RHEL-06-000195
##The audit system must be configured to audit all discretionary access control permission modifications using removexattr.

grep -w "removexattr" /etc/audit/audit.rules >/dev/null 2>&1 &

spinner $!
output "V-38563" $? ${SETLANG}
################

##RHEL-06-000196
##The audit system must be configured to audit all discretionary access control permission modifications using setxattr.

grep -w "setxattr" /etc/audit/audit.rules >/dev/null 2>&1 &

spinner $!
output "V-38565" $? ${SETLANG}
################

##RHEL-06-000197
##The audit system must be configured to audit failed attempts to access files and programs.

bash scripts/check-auditd.sh failed-access-files-programs >/dev/null 2>&1 &

spinner $!
output "V-38566" $? ${SETLANG}
################

##RHEL-06-000198
##The audit system must be configured to audit all use of setuid and setgid programs.

bash scripts/check-auditd.sh setuid-setgid >/dev/null 2>&1 &

spinner $!
output "V-38567" $? ${SETLANG}
################

##RHEL-06-000199
##The audit system must be configured to audit successful file system mounts.

grep -w "mount" /etc/audit/audit.rules >/dev/null 2>&1 &

spinner $!
output "V-38568" $? ${SETLANG}
################

##RHEL-06-000200
##The audit system must be configured to audit user deletions of files and programs.

bash scripts/check-auditd.sh deletions >/dev/null 2>&1 &

spinner $!
output "V-38575" $? ${SETLANG}
################

##RHEL-06-000201
##The audit system must be configured to audit changes to the /etc/sudoers file.

auditctl -l | grep "watch=/etc/sudoers" >/dev/null 2>&1 &

spinner $!
output "V-38578" $? ${SETLANG}
################

##RHEL-06-000202
##The audit system must be configured to audit the loading and unloading of dynamic kernel modules.

bash scripts/check-auditd.sh kernel-modules >/dev/null 2>&1 &

spinner $!
output "V-38580" $? ${SETLANG}
################

##RHEL-06-000203
##The xinetd service must be disabled if no network services utilizing it are enabled.

bash scripts/check-services.sh xinetd >/dev/null 2>&1 &

spinner $!
output "V-38582" $? ${SETLANG}
################

##RHEL-06-000204
##The xinetd service must be uninstalled if no network services utilizing it are enabled.

bash scripts/check-packages.sh xinetd >/dev/null 2>&1 &

spinner $!
output "V-38584" $? ${SETLANG}
################

##RHEL-06-000206
##The telnet-server package must not be installed.

bash scripts/check-packages.sh telnetd >/dev/null 2>&1 &

spinner $!
output "V-38587" $? ${SETLANG}
################

##RHEL-06-000211
##The telnet daemon must not be running.

bash scripts/check-services.sh telnetd >/dev/null 2>&1 &

spinner $!
output "V-38589" $? ${SETLANG}
################

##RHEL-06-000213
##The rsh-server package must not be installed.

bash scripts/check-packages.sh rsh-server >/dev/null 2>&1 &

spinner $!
output "V-38591" $? ${SETLANG}
################

##RHEL-06-000214
##The rshd service must not be running.

bash scripts/check-services.sh rshd >/dev/null 2>&1 &

spinner $!
output "V-38594" $? ${SETLANG}
################

##RHEL-06-000216
##The rexecd service must not be running.

bash scripts/check-services.sh rexecd >/dev/null 2>&1 &

spinner $!
output "V-38598" $? ${SETLANG}
################

##RHEL-06-000218
##The rlogind service must not be running.

bash scripts/check-services.sh rlogind >/dev/null 2>&1 &

spinner $!
output "V-38602" $? ${SETLANG}
################

##RHEL-06-000220
##The NIS(ypserv) package must not be installed.

bash scripts/check-packages.sh nis >/dev/null 2>&1 &

spinner $!
output "V-38603" $? ${SETLANG}
################

##RHEL-06-000221
##The nis(ypbind) service must not be running.

bash scripts/check-services.sh nis >/dev/null 2>&1 &

spinner $!
output "V-38604" $? ${SETLANG}
################

##RHEL-06-000222
##The tftp-server package must not be installed unless required.

bash scripts/check-packages.sh tftpd >/dev/null 2>&1 &

spinner $!
output "V-38606" $? ${SETLANG}
################

##RHEL-06-000223
##The TFTP service must not be running.

bash scripts/check-services.sh tftpd >/dev/null 2>&1 &

spinner $!
output "V-38609" $? ${SETLANG}
################

##RHEL-06-000224
##The cron service must be running.

bash scripts/check-services.sh cron >/dev/null 2>&1 &

spinner $!
output "V-38605" $? ${SETLANG}
################

##RHEL-06-000227
##The SSH daemon must be configured to use only the SSHv2 protocol.

bash scripts/check-ssh.sh Protocol >/dev/null 2>&1 &

spinner $!
output "V-38607" $? ${SETLANG}
################

##RHEL-06-000230
##The SSH daemon must set a timeout interval on idle sessions.

sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/ssh/sshd_config | grep "ClientAliveInterval" >/dev/null 2>&1 &

spinner $!
output "V-38608" $? ${SETLANG}
################

##RHEL-06-000231
##The SSH daemon must set a timeout count on idle sessions.

sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/ssh/sshd_config | grep "ClientAliveCountMax" >/dev/null 2>&1 &

spinner $!
output "V-38610" $? ${SETLANG}
################

##RHEL-06-000234
##The SSH daemon must ignore .rhosts files.

bash scripts/check-ssh.sh rhosts >/dev/null 2>&1 &

spinner $!
output "V-38611" $? ${SETLANG}
################

##RHEL-06-000236
##The SSH daemon must not allow host-based authentication.

bash scripts/check-ssh.sh hostauth >/dev/null 2>&1 &

spinner $!
output "V-38612" $? ${SETLANG}
################

##RHEL-06-000237
##The system must not permit root logins using remote access programs such as ssh.

bash scripts/check-ssh.sh permitroot >/dev/null 2>&1 &

spinner $!
output "V-38613" $? ${SETLANG}
################

##RHEL-06-000239
##The SSH daemon must not allow authentication using an empty password.

bash scripts/check-ssh.sh emptypassword >/dev/null 2>&1 &

spinner $!
output "V-38615" $? ${SETLANG}
################

##RHEL-06-000241
##The SSH daemon must not permit user environment settings.

bash scripts/check-ssh.sh emptypasswordenvironment >/dev/null 2>&1 &

spinner $!
output "V-38616" $? ${SETLANG}
################

##RHEL-06-000243
##The SSH daemon must be configured to use only FIPS 140-2 approved ciphers.

bash scripts/check-ssh-ciphers.sh > /dev/null 2>&1 &

spinner $!
output "V-38617" $? ${SETLANG}
################

##RHEL-06-000246
##The avahi service must be disabled.

bash scripts/check-services.sh avahi-daemon >/dev/null 2>&1 &

spinner $!
output "V-38618" $? ${SETLANG}
################

##RHEL-06-000247
##The system clock must be synchronized continuously, or at least daily.

bash scripts/check-services.sh ntp >/dev/null 2>&1 &

spinner $!
output "V-38620" $? ${SETLANG}
################

##RHEL-06-000248
##The system clock must be synchronized to an authoritative time source.

bash scripts/check-ntp-sources.sh >/dev/null 2>&1 &

spinner $!
output "V-38621" $? ${SETLANG}
################

##RHEL-06-000249
##Mail relaying must be restricted.

bash scripts/check-postfix.sh >/dev/null 2>&1 &

spinner $!
output "V-38622" $? ${SETLANG}
################

##RHEL-06-000252
##If the system is using LDAP for authentication or account information, the system must use a TLS connection using FIPS 140-2 approved cryptographic algorithms.

#Waiting to figure out

#spinner $!
#output "V-38625" $? ${SETLANG}
################

##RHEL-06-000253
##The LDAP client must use a TLS connection using trust certificates signed by the site CA.

#Waiting to figure out

#spinner $!
#output "V-38626" $? ${SETLANG}
################

##RHEL-06-000256
##The openldap-servers package must not be installed unless required.

bash scripts/check-packages.sh sldap>/dev/null 2>&1 &

spinner $!
output "V-38627" $? ${SETLANG}
################

##RHEL-06-000257
##The graphical desktop environment must set the idle timeout to no more than 15 minutes.

#spinner $!
#output "V-38629" $? ${SETLANG}
################

##RHEL-06-000258
##The graphical desktop environment must automatically lock after 15 minutes of inactivity and the system must require user reauthentication to unlock the environment.

#spinner $!
#output "V-38630" $? ${SETLANG}
################

##RHEL-06-000259
##The graphical desktop environment must have automatic lock enabled.

#spinner $!
#output "V-38638" $? ${SETLANG}
################

##RHEL-06-000260
##The system must display a publicly-viewable pattern during a graphical desktop environment session lock.

#spinner $!
#output "V-38639" $? ${SETLANG}
################

##RHEL-06-000262
##The atd service must be disabled.

bash scripts/check-services.sh atd >/dev/null 2>&1 &

spinner $!
output "V-38641" $? ${SETLANG}
################

##RHEL-06-000269
##Remote file systems must be mounted with the nodev option.
if [ "$(mount | grep nfs | wc -l)" -gt 0 ];then 
bash scripts/check-nfs.sh nodev >/dev/null 2>&1 &

spinner $!
output "V-38652" $? ${SETLANG}
fi
################

##RHEL-06-000270
##Remote file systems must be mounted with the nosuid option.
if [ "$(mount | grep nfs | wc -l)" -gt 0 ];then 
bash scripts/check-nfs.sh nosuid >/dev/null 2>&1 &

spinner $!
output "V-38654" $? ${SETLANG}
fi
################

##RHEL-06-000271
##The noexec option must be added to removable media partitions.
if [ "$(grep -Hv ^0$ /sys/block/*/removable | sed s/removable:.*$/device\\/uevent/ | xargs grep -H ^DRIVER=sd | sed s/device.uevent.*$/size/ | xargs grep -Hv ^0$ | cut -d / -f 4 | wc -l)" -gt 0 ];then 
bash scripts/check-removable.sh >/dev/null 2>&1 &

spinner $!
output "V-38655" $? ${SETLANG}
fi
################

##RHEL-06-000272
##The system must use SMB client signing for connecting to samba servers using smbclient.

bash scripts/check-depends.sh smb-signing >/dev/null 2>&1 &

spinner $!
output "V-38656" $? ${SETLANG}
################

##RHEL-06-000273
##The system must use SMB client signing for connecting to samba servers using mount.cifs.

bash scripts/check-depends.sh smb-sec >/dev/null 2>&1 &

spinner $!
output "V-38657" $? ${SETLANG}
################

##RHEL-06-000274
##The system must prohibit the reuse of passwords within twenty-four iterations.

grep remember /etc/pam.d/common-auth /etc/pam.d/common-password >/dev/null 2>&1 &

spinner $!
output "V-38658" $? ${SETLANG}
################

##RHEL-06-000275
##The operating system must employ cryptographic mechanisms to protect information in storage.

dmsetup status | grep -i "crypt" >/dev/null 2>&1 &

spinner $!
output "V-38659" $? ${SETLANG}
################

##RHEL-06-000276
##The operating system must protect the confidentiality and integrity of data at rest.

dmsetup status | grep -i "crypt" >/dev/null 2>&1 &

spinner $!
output "V-38661" $? ${SETLANG}
################

##RHEL-06-000277
##The operating system must employ cryptographic mechanisms to prevent unauthorized disclosure of data at rest unless otherwise protected by alternative physical measures.

dmsetup status | grep -i "crypt" >/dev/null 2>&1 &

spinner $!
output "V-38662" $? ${SETLANG}
################

##RHEL-06-000278
##The system package management tool must verify permissions on all files and directories associated with the audit package.

bash scripts/check-auditd-package.sh permission >/dev/null 2>&1 &

spinner $!
output "V-38663" $? ${SETLANG}
################

##RHEL-06-000279
##The system package management tool must verify ownership on all files and directories associated with the audit package.

bash scripts/check-auditd-package.sh owner >/dev/null 2>&1 &

spinner $!
output "V-38664" $? ${SETLANG}
################

##RHEL-06-000280
##The system package management tool must verify group-ownership on all files and directories associated with the audit package.

bash scripts/check-auditd-package.sh group-owner >/dev/null 2>&1 &

spinner $!
output "V-38665" $? ${SETLANG}
################

##RHEL-06-000281
##The system package management tool must verify group-ownership on all files and directories associated with the audit package.

bash scripts/check-auditd-package.sh file-hashes >/dev/null 2>&1 &

spinner $!
output "V-38637" $? ${SETLANG}
################

##RHEL-06-000282
##There must be no world-writable files on the system.

bash scripts/check-world-writable.sh >/dev/null 2>&1 &

spinner $!
output "V-38643" $? ${SETLANG}
################

##RHEL-06-000286
##The x86 Ctrl-Alt-Delete key sequence must be disabled.

bash scripts/check-ctrl-alt-del.sh >/dev/null 2>&1 &

spinner $!
output "V-38668" $? ${SETLANG}
################

##RHEL-06-000287
##The postfix service must be enabled for mail delivery.

bash scripts/check-services.sh postfix >/dev/null 2>&1 &

spinner $!
output "V-38669" $? ${SETLANG}
################

##RHEL-06-000288
##The sendmail package must be removed.

bash scripts/check-packages.sh sendmail >/dev/null 2>&1 &

spinner $!
output "V-38671" $? ${SETLANG}
################

##RHEL-06-000290
##X Windows must not be enabled unless required.

bash scripts/check-services.sh x11-common >/dev/null 2>&1 &

spinner $!
output "V-38674" $? ${SETLANG}
################

##RHEL-06-000291
##The xorg-x11-server-common (X Windows) package must not be installed, unless required.

bash scripts/check-packages.sh x11-common >/dev/null 2>&1 &

spinner $!
output "V-38676" $? ${SETLANG}
################

##RHEL-06-000294
##All GIDs referenced in /etc/passwd must be defined in /etc/group

check scripts/check-gids.sh >/dev/null 2>&1 &

spinner $!
output "V-38681" $? ${SETLANG}
################

##RHEL-06-000296
##All accounts on the system must have unique user or account names

check scripts/check-uniq-names.sh >/dev/null 2>&1 &

spinner $!
output "V-38683" $? ${SETLANG}
################

##RHEL-06-000299
##The system must require passwords to contain no more than three consecutive repeating characters.

bash scripts/check-password.sh /etc/pam.d/common-password pam_cracklib.so maxrepeat lt 3 > /dev/null 2>&1 &

spinner $!
output "V-38693" $? ${SETLANG}
################

##RHEL-06-000302
##A file integrity tool must be used at least weekly to check for unauthorized file changes, particularly the addition of unauthorized system libraries or binaries, or for unauthorized modification to authorized system libraries or binaries.

bash scripts/check-aide-cron.sh > /dev/null 2>&1 &

spinner $!
output "V-38695" $? ${SETLANG}
################

##RHEL-06-000308
##Process core dumps must be disabled unless needed.

bash scripts/check-limits.sh core-dumps > /dev/null 2>&1 &

spinner $!
output "V-38675" $? ${SETLANG}
################

##RHEL-06-000309
##The NFS server must not have the insecure file locking option enabled.

bash scripts/check-nfs-insecure.sh > /dev/null 2>&1 &

spinner $!
output "V-38677" $? ${SETLANG}
################

##RHEL-06-000313
##The audit system must identify staff members to receive notifications of audit log storage volume capacity issues.  

bash scripts/check-auditd.sh action_mail_acct > /dev/null 2>&1 &

spinner $!
output "V-38680" $? ${SETLANG}
################

##RHEL-06-000315
##The Bluetooth kernel module must be disabled.

bash scripts/check-bluetooth.sh > /dev/null 2>&1 &

spinner $!
output "V-38682" $? ${SETLANG}
################

##RHEL-06-000319
##The system must limit users to 10 simultaneous system logins, or a site-defined number, in accordance with operational requirements.

bash scripts/check-limits.sh maxlogins > /dev/null 2>&1 &

spinner $!
output "V-38684" $? ${SETLANG}
################

##RHEL-06-000320
##The systems local firewall must implement a deny-all, allow-by-exception policy for forwarded packets.

iptables -L FORWARD | head -n1 | grep "FORWARD.*DROP" >/dev/null 2>&1 &

spinner $!
output "V-38686" $? ${SETLANG}
################

##RHEL-06-000331
##The Bluetooth service must be disabled.

bash scripts/check-services.sh bluetooth >/dev/null 2>&1 &

spinner $!
output "V-38691" $? ${SETLANG}
################

##RHEL-06-000334
##Accounts must be locked upon 35 days of inactivity.

bash scripts/check-inactive.sh >/dev/null 2>&1 &

spinner $!
output "V-38692" $? ${SETLANG}
################

##RHEL-06-000335
##The operating system must manage information system identifiers for users and devices by disabling the user identifier after an organization defined time period of inactivity.

bash scripts/check-inactive.sh >/dev/null 2>&1 &

spinner $!
output "V-38694" $? ${SETLANG}
################

##RHEL-06-000336
##The sticky bit must be set on all public directories.

bash scripts/check-sticky-bit.sh >/dev/null 2>&1 &

spinner $!
output "V-38697" $? ${SETLANG}
################

##RHEL-06-000337
##All public directories must be owned by a system account.

bash scripts/check-public-dir-owned.sh >/dev/null 2>&1 &

spinner $!
output "V-38699" $? ${SETLANG}
################

##RHEL-06-000338
##The TFTP daemon must operate in secure mode which provides access only to a single directory on the host file system.

sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/inetd.conf | grep "tftp.*\-s" >/dev/null 2>&1 &

spinner $!
output "V-38701" $? ${SETLANG}
################

##RHEL-06-000339
##The FTP daemon must be configured for logging or verbose mode.

sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/vsftpd.conf | grep -i "xferlog_enable.*YES" >/dev/null 2>&1 &

spinner $!
output "V-38702" $? ${SETLANG}
################

##RHEL-06-000345
##The system default umask in /etc/login.defs must be 077.
##For more detial :http://stackoverflow.com/questions/10220531/how-to-set-system-wide-umask

sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/login.defs  | grep -i "umask.*077" >/dev/null 2>&1 &

spinner $!
output "V-38645" $? ${SETLANG}
################

##RHEL-06-000346
##The system default umask for daemons must be 027 or 022.
##For more detial :http://unix.stackexchange.com/questions/36220/how-to-set-umask-for-a-system-user

sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/init.d/rc | grep -i "umask.*027\|umask.*022" >/dev/null 2>&1 &

spinner $!
output "V-38646" $? ${SETLANG}
################

##RHEL-06-000347
##There must be no .netrc files on the system.

bash scripts/check-netrc.sh >/dev/null 2>&1 &

spinner $!
output "V-38619" $? ${SETLANG}
################

##RHEL-06-000356
##The system must require administrator action to unlock an account locked by excessive failed login attempts.

bash scripts/check-password.sh /etc/pam.d/common-auth pam_tally unlock_time lt 604800 > /dev/null 2>&1 &

spinner $!
output "V-38592" $? ${SETLANG}
################

##RHEL-06-000372
##The operating system, upon successful logon/access, must display to the user the number of unsuccessful logon/access attempts since the last successful logon/access.

sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/pam.d/common-session | grep -i "pam_lastlog.so.*showfailed" > /dev/null 2>&1 &

spinner $!
output "V-38501" $? ${SETLANG}
################

##RHEL-06-000383
##Audit log files must have mode 0640 or less permissive.

bash scripts/check-mode.sh `grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//` 640 > /dev/null 2>&1 &

spinner $!
output "V-38498" $? ${SETLANG}
################

##RHEL-06-000384
##Audit log files must be owned by root.

grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %U | grep root > /dev/null 2>&1 &

spinner $!
output "V-38495" $? ${SETLANG}
################

##RHEL-06-000385
##Audit log directories must have mode 0755 or less permissive.

bash scripts/check-mode.sh `grep "^log_file" /etc/audit/auditd.conf|sed 's/^[^/]*//; s/[^/]*$//'` 755 > /dev/null 2>&1 &

spinner $!
output "V-38493" $? ${SETLANG}
################

##RHEL-06-000503
##The operating system must enforce requirements for the connection of mobile devices to operating systems.

grep -r usb-storage  /etc/modprobe.d > /dev/null 2>&1 &

spinner $!
output "V-38490" $? ${SETLANG}
################

##RHEL-06-000507
##The operating system, upon successful logon, must display to the user the date and time of the last logon or access via ssh.

sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/ssh/sshd_config | grep -i "^PrintLastLog.*yes" > /dev/null 2>&1 &

spinner $!
output "V-38484" $? ${SETLANG}
################

##RHEL-06-000509
##The system must forward audit records to the syslog service.

bash scripts/check-audisp.sh > /dev/null 2>&1 &

spinner $!
output "V-38471" $? ${SETLANG}
################

##RHEL-06-000510
##The audit system must take appropriate action when the audit storage volume is full.

bash scripts/check-auditd.sh disk_full_action > /dev/null 2>&1 &

spinner $!
output "V-38468" $? ${SETLANG}
################

##RHEL-06-000511
##The audit system must take appropriate action when there are disk errors on the audit storage volume.

bash scripts/check-auditd.sh disk_error_action > /dev/null 2>&1 &

spinner $!
output "V-38464" $? ${SETLANG}
################

##RHEL-06-000514
##The package management tool must cryptographically verify the authenticity of all software packages during installation.

bash scripts/check-apt-gpg.sh > /dev/null 2>&1 &

spinner $!
output "V-38462" $? ${SETLANG}
################

##RHEL-06-000515
##The NFS server must not have the all_squash option enabled.

bash scripts/check-nfs-all-squash.sh > /dev/null 2>&1 &

spinner $!
output "V-38460" $? ${SETLANG}
################

##RHEL-06-000521
##The mail system must forward all mail for root to one or more system administrators.

postmap -q root `postconf alias_maps | awk -F '=' '{print $2}'` > /dev/null 2>&1 &

spinner $!
output "V-38446" $? ${SETLANG}
################

##RHEL-06-000522
##Audit log files must be group-owned by root.

grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %G | grep root > /dev/null 2>&1 &

spinner $!
output "V-38445" $? ${SETLANG}
################

##RHEL-06-000523
##The systems local IPv6 firewall must implement a deny-all, allow-by-exception policy for inbound packets.

ip6tables -L INPUT | head -n1 | grep "INPUT.*DROP" > /dev/null 2>&1 &

spinner $!
output "V-38444" $? ${SETLANG}
################

##RHEL-06-000525
##Auditing must be enabled at boot by setting a kernel parameter.

grep "audit=1" /boot/grub/grub.cfg >/dev/null 2>&1 &

spinner $!
output "V-38438" $? ${SETLANG}
################

##RHEL-06-000526
##Automated file system mounting tools must not be enabled unless needed.

bash scripts/check-services.sh autofs >/dev/null 2>&1 &

spinner $!
output "V-38437" $? ${SETLANG}
################

##RHEL-06-000528
##The noexec option must be added to the /tmp partition.

sed -e '/^#/d' -e '/^[ \t][ \t]*#/d' -e 's/#.*$//' -e '/^$/d' /etc/fstab | grep "/tmp.*noexec" >/dev/null 2>&1 &

spinner $!
output "V-57569" $? ${SETLANG}
################

##RHEL-06-000529
##The sudo command must require authentication.

bash scripts/check-sudo.sh >/dev/null 2>&1 &

spinner $!
output "V-58901" $? ${SETLANG}
################




###################################


printf "\n\nLog file at: $LOG \n" 
