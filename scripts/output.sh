output()
{   
    case "$1" in 
    
    V-38455)  log_msg $2 'The system must use a separate file system for /tmp.'
              if [ $2 -ne 0 ];then
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000001\n\nVulnerability Discussion: The "/tmp" partition is used as temporary storage by many programs. Placing "/tmp" in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it.\n\nFix Text: The "/tmp" directory is a world-writable directory used for temporary file storage. Ensure it hasits own partition or logical volume at installation time, or migrate it using LVM.\n\n######################\n\n' >> $LOG
              fi
              ;;

    V-38456)  log_msg $2 'The system must use a separate file system for /var.'
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000002\n\nVulnerability Discussion: Ensuring that "/var" is mounted on its own partition enables the setting of more restrictive mount options. This helps protect system services such as daemons or other programs which use it. It is not uncommon for the "/var" directory to contain world-writable directories, installed by other software packages.\n\nFix Text: The "/var" directory is used by daemons and other system services to store frequently-changing data. Ensure that "/var" has its own partition or logical volume at installation time, or migrate it using LVM.\n\n######################\n\n' >> $LOG
              fi
              ;;

    V-38463)  log_msg $2 'The system must use a separate file system for /var/log.'
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000003\n\nVulnerability Discussion: Placing "/var/log" in its own partition enables better separation between log files and other files in "/var/".\n\nFix text: System logs are stored in the "/var/log" directory. Ensure that it has its own partition or logical volume at installation time, or migrate it using LVM.\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38467)  log_msg $2 'The system must use a separate file system for the system audit data path.'
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000004\n\nVulnerability Discussion: Placing "/var/log/audit" in its own partition enables better separation between audit files and other files, and helps ensure that auditing cannot be halted due to the partition running out of space.\n\nFix text: Audit logs are stored in the "/var/log/audit" directory. Ensure that it has its own partition or logical
volume at installation time, or migrate it later using LVM. Make absolutely certain that it is large enough to
store all audit logs that will be created by the auditing daemon.\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38470)  log_msg $2 'The audit system must alert designated staff members when the audit storage volume approaches capacity.'
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000005\n\nVulnerability Discussion: Notifying administrators of an impending disk space problem may allow them to take corrective action prior to any disruption.\n\nFix text: The "auditd" service can be configured to take an action when disk space starts to run low. Edit the file "/etc/audit/auditd.conf". Modify the following line, substituting [ACTION] appropriately:\n\n
space_left_action = [ACTION]\n\nPossible values for [ACTION] are described in the "auditd.conf" man page. These include:\n\n"ignore"\n"syslog"\n"email"\n"exec"\n"suspend"\n"single"\n"halt"\n\nSet this to "email" (instead of the default, which is "suspend") as it is more likely to get prompt attention. The"syslog" option is acceptable, provided the local log management infrastructure notifies an appropriate
administrator in a timely manner.\n\nRHEL-06-000521 ensures that the email generated through the operation "space_left_action" will be sent to
an administrator.\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38473)  log_msg $2 'The system must use a separate file system for user home directories.'
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000007\n\nVulnerability Discussion: Ensuring that "/home" is mounted on its own partition enables the setting of more restrictive mount options, and also helps ensure that users cannot trivially fill partitions used for log or audit data storage.\n\nFix text: If user home directories will be stored locally, create a separate partition for "/home" at installation time (or migrate it later using LVM). If "/home" will be mounted from another system such as an NFS server, then creating a separate partition is not necessary at installation time, and the mountpoint can instead be configured later.  \n\n######################\n\n' >> $LOG
              fi
              ;;

    V-38476)  log_msg $2 'Vendor-provided cryptographic certificates must be installed to verify the integrity of system software.' ##Ported
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000008\n\nVulnerability Discussion: The Debian GPG keys are necessary to cryptographically verify packages are from Debian.\n\nAt this checking script("scripts/check-apt-key.sh"). We check :\n\nDebian8/jessie archive key,security archive signing key,stable release key\nDebian 7/Wheezy archive key,stable key\nDebian 6/Squeeze archive key,stable key.\n\nFor the detial could vist the : https://ftp-master.debian.org/keys.html\n\nFix text: To ensure the system can cryptographically verify base software packages come from Debian,the Red Hat GPG keys must be installed properly. To install the Debian GPG keys, run:\n\napt-key add "KEY"\n\nAnyone could find the key at:https://ftp-master.debian.org/keys.html\n\n######################\n\n' >> $LOG
              fi
              ;;

#wait for porting
    V-38478)  log_msg $2 'The Red Hat Network Service (rhnsd) service must not be running, unless using RHN or an RHN Satellite.'
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000009\n\nVulnerability Discussion: \n\nFix text: \n\n######################\n\n' >> $LOG
              fi
              ;;

    V-38481)  log_msg $2 'System security patches and updates must be installed and up-to-date.' ##Ported
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000011\n\nVulnerability Discussion: Installing software updates is a fundamental mitigation against the exploitation of publicly-known vulnerabilities.\n\nFix text: If the system can connect to a Debian mirrors, run the following command to install updates:\n\n#apt-get update && apt-get upgrade\n\n######################\n\n' >> $LOG
              fi
              ;;

#wait for porting
    V-38483)  log_msg $2 'The system package management tool must cryptographically verify the authenticity of system software packages during installation.'
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000013\n\nVulnerability Discussion: \n\nFix text: \n\n######################\n\n' >> $LOG
              fi
              ;;

#wait for porting
    V-38487)  log_msg $2 'The system package management tool must cryptographically verify the authenticity of all
software packages during installation.'
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000015\n\nVulnerability Discussion: Ensuring all packages cryptographic signatures are valid prior to installation ensures the provenance of the software and protects against malicious tampering.\n\nFix text: \n\n######################\n\n' >> $LOG
              fi
              ;;

    V-38489)  log_msg $2 'A file integrity tool must be installed.(AIDE)' ##Ported
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000016\n\nVulnerability Discussion: The AIDE package must be installed if it is to be available for integrity checking.\n\nFix text: Install the AIDE package with the command:\n\n#apt-get install aide\n\n######################\n\n' >> $LOG
              fi
              ;;

    V-51337)  log_msg $2 'The system must use a Linux Security Module at boot time.(AppArmor)' ##Ported
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000017\n\nVulnerability Discussion: Disabling a major host protection feature, such as Apparmor, at boot time prevents it from confining system services at boot time. Further, it increases the chances that it will remain off during system operation.\n\nFix text: Install the Apparmor package with the command:\n\n#apt-get install apparmor apparmor-profiles apparmor-utils\n\nAnd add \n\nGRUB_CMDLINE_LINUX=" apparmor=1 security=apparmor"\n\nTo/etc/default/grub\n\n#update-grub\n\n#reboot\n\nFor detial could visit:https://wiki.debian.org/AppArmor/HowToUse\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-51391)  log_msg $2 'A file integrity baseline must be created.'
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000018\n\nVulnerability Discussion: For AIDE to be effective, an initial database of "known-good" information about files must be captured and it should be able to be verified against the installed files.\n\nFix text: Run the following command to generate a new database:\n\n#aideinit\n\nBy default, the database will be written to the file "/var/lib/aide/aide.db.new.gz". Storing the database, the configuration file "/etc/aide.conf", and the binary "/usr/sbin/aide" (or hashes of these files), in a secure location (such as on read-only media) provides additional assurance about their integrity.\n\nThe newlygenerated database can be installed as follows:\n\n#cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db\n\nTo initiate a manual check, run the following command:\n\n#/usr/sbin/aide --check\n\nIf this check produces any unexpected output, investigate.\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38491)  log_msg $2 'There must be no .rhosts or hosts.equiv files on the system.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000019\n\nVulnerability Discussion: Trust files are convenient, but when used in conjunction with the R-services, they can allow unauthenticated access to a system.\n\nFix text: The files "/etc/hosts.equiv" and "~/.rhosts" (in each user\047s home directory) list remote hosts and users that are trusted by the local system when using the rshd daemon. To remove these files, run the following command to delete them from any location.\n\n#rm /etc/hosts.equiv\n\n#rm ~/.rhosts\n\n######################\n\n' >> $LOG
              fi
              ;;

#wait for porting
    V-51363)  log_msg $2 'The system must use a Linux Security Module configured to enforce limits on system services.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000020\n\nVulnerability Discussion: Setting the Apparmor state to enforcing ensures Apparmor is able to confine potentially compromised processes to the security policy, which is designed to prevent them from causing damage to the system or further elevating their privileges.\n\nFix text: \n\n######################\n\n' >> $LOG
              fi
              ;;

#wait for porting
    V-51369)  log_msg $2 'The system must use a Linux Security Module configured to limit the privileges of system services.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000023\n\nVulnerability Discussion: \n\nFix text: \n\n######################\n\n' >> $LOG
              fi
              ;;
#wait for porting
    V-51379)  log_msg $2 'All device files must be monitored by the system Linux Security Module.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000025\n\nVulnerability Discussion: \n\nFix text: \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38492)  log_msg $2 'The system must prevent the root account from logging in from virtual consoles.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000027\n\nVulnerability Discussion: Preventing direct root login to virtual console devices helps ensure accountability for actions taken on the system using the root account.\n\nFix text: To restrict root logins through the (deprecated) virtual console devices, ensure lines of this form do not appear in "/etc/securetty":\n\nvc/1\nvc/2\nvc/3\nvc/4\n\nNote: Virtual console entries are not limited to those listed above. Any lines starting with "vc/" followed by numerals should be removed.\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38494)  log_msg $2 'The system must prevent the root account from logging in from serial consoles.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000028\n\nVulnerability Discussion: Preventing direct root login to serial port interfaces helps ensure accountability for actions taken on the systems using the root account.\n\nFix text: To restrict root logins on serial ports, ensure lines of this form do not appear in "/etc/securetty":\n\nttyS0\n\nttyS1\n\nNote: Serial port entries are not limited to those listed above. Any lines starting with "ttyS" followed by numerals should be removed\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38496)  log_msg $2 'Default operating system accounts, other than root, must be locked.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000029\n\nVulnerability Discussion: Disabling authentication for default system accounts makes it more difficult for attackers to make use of them to compromise a system.\n\nFix text: Some accounts are not associated with a human user of the system, and exist to perform some administrative function. An attacker should not be able to log into these accounts.\n\nDisable logon access to these accounts with the command:\n\n#passwd -l [SYSACCT]\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38497)  log_msg $2 'The system must not have accounts configured with blank or null passwords.'  ##Ported
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000030\n\nVulnerability Discussion: If an account has an empty password, anyone could log in and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.\n\nFix text: If an account is configured for password authentication but does not have an assigned password, it may be possible to log onto the account without authentication. Remove any instances of the "nullok" option in "/etc/pam.d/common-password" to prevent logons with empty passwords.\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38499)  log_msg $2 'The /etc/passwd file must not contain password hashes.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000031\n\nVulnerability Discussion: The hashes for all user account passwords should be stored in the file "/etc/shadow" and never in "/etc/passwd", which is readable by all users.\n\nFix text: If any password hashes are stored in "/etc/passwd" (in the second field, instead of an "x"), the cause of this misconfiguration should be investigated. The account should have its password reset and the hash should be properly stored, or the account should be deleted entirely.  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38500)  log_msg $2 'The root account must be the only account having a UID of 0.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000032\n\nVulnerability Discussion: An account has root authority if it has a UID of 0. Multiple accounts with a UID of 0 afford more opportunity for potential intruders to guess a password for a privileged account. Proper
configuration of sudo is recommended to afford multiple system administrators access to root privileges in an accountable manner.\n\nFix text: If any account other than root has a UID of 0, this misconfiguration should be investigated and the accounts other than root should be removed or have their UID changed.\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38502)  log_msg $2 'The /etc/shadow file must be owned by root.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000033\n\nVulnerability Discussion: The "/etc/shadow" file contains the list of local system accounts and stores password hashes. Protection of this file is critical for system security. Failure to give ownership of this file to root provides the designated owner with access to sensitive information which could weaken the system security posture.\n\nFix text: To properly set the owner of "/etc/shadow", run the command:\n\n#chown root /etc/shadow\n\n##################\n\n' >> $LOG
              fi
              ;;
    V-38503)  log_msg $2 'The /etc/shadow file must be group-owned by root.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000034\n\nVulnerability Discussion: The "/etc/shadow" file stores password hashes. Protection of this file is critical for system security.\n\nFix text: To properly set the group owner of "/etc/shadow", run the command:\n\n#chgrp root /etc/shadow\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38504)  log_msg $2 'The /etc/shadow file must have mode 0000.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000035\n\nVulnerability Discussion: The "/etc/shadow" file contains the list of local system accounts and stores password hashes. Protection of this file is critical for system security. Failure to give ownership of this file to root provides the designated owner with access to sensitive information which could weaken the system security posture.\n\nFix text: To properly set the permissions of "/etc/shadow", run the command:\n\n#chmod 0000 /etc/shadow\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38443)  log_msg $2 'The /etc/gshadow file must be owned by root.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000036\n\nVulnerability Discussion: The "/etc/gshadow" file contains group password hashes. Protection of this file is critical for system security.\n\nFix text: To properly set the owner of "/etc/gshadow", run the command:\n\n#chown root /etc/gshadow\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38448)  log_msg $2 'The /etc/gshadow file must be group-owned by root.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000037\n\nVulnerability Discussion: The "/etc/gshadow" file contains group password hashes. Protection of this file is critical for system security.\n\nFix text: To properly set the group owner of "/etc/gshadow", run the command:\n\n#chgrp root /etc/gshadow\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38449)  log_msg $2 'The /etc/gshadow file must have mode 0000.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000038\n\nVulnerability Discussion: The /etc/gshadow file contains group password hashes. Protection of this file is critical for system security.\n\nFix text: To properly set the permissions of "/etc/gshadow", run the command:\n\n#chmod 0000 /etc/gshadow\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38450)  log_msg $2 'The /etc/passwd file must be owned by root.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000039\n\nVulnerability Discussion: The "/etc/passwd" file contains information about the users that are configured on the system. Protection of this file is critical for system security.\n\nFix text: To properly set the owner of "/etc/passwd", run the command:\n\n#chown root /etc/passwd\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38451)  log_msg $2 'The /etc/passwd file must be group-owned by root.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000040\n\nVulnerability Discussion: The "/etc/passwd" file contains information about the users that are configured on the system. Protection of this file is critical for system security.\n\nFix text: To properly set the group owner of "/etc/passwd", run the command:\n\n#chgrp root /etc/passwd\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38457)  log_msg $2 'The /etc/passwd file must have mode 0644 or less permissive.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000041\n\nVulnerability Discussion: If the "/etc/passwd" file is writable by a group-owner or the world the risk of its compromise is increased. The file contains the list of accounts on the system and associated information, and protection of this file is critical for system security.\n\nFix text: To properly set the permissions of "/etc/passwd", run the command:\n\n#chmod 0644 /etc/passwd\n\n######################\n\n' >> $LOG
              fi
              ;;

    V-38458)  log_msg $2 'The /etc/group file must be owned by root.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000042\n\nVulnerability Discussion: The "/etc/group" file contains information regarding groups that are configured on the system. Protection of this file is important for system security.\n\nFix text: To properly set the owner of "/etc/group", run the command:\n\n#chown root /etc/group\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38459)  log_msg $2 'The /etc/group file must be group-owned by root.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000043\n\nVulnerability Discussion: The "/etc/group" file contains information regarding groups that are configured on the system. Protection of this file is important for system security.\n\nFix text: To properly set the group owner of "/etc/group", run the command:\n\n#chgrp root /etc/group\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38461)  log_msg $2 'The /etc/group file must have mode 0644 or less permissive.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000044\n\nVulnerability Discussion: The "/etc/group" file contains information regarding groups that are configured on the system. Protection of this file is important for system security.\n\nFix text: To properly set the permissions of "/etc/group", run the command:\n\n#chmod 0644 /etc/group\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38465)  log_msg $2 'Library files must have mode 0755 or less permissive.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000045\n\nVulnerability Discussion: Files from shared library directories are loaded into the address space of processes (including privileged ones) or of the kernel itself at runtime. Restrictive permissions are necessary to protect the integrity of the system.\n\nFix text: ystem-wide shared library files, which are linked to executables during process load time or run
time, are stored in the following directories by default:\n\n/lib\n/lib64\n/usr/lib\n/usr/lib64\n\nIf any file in these directories is found to be group-writable or world-writable, correct its permission with the following command:\n\n#chmod go-w [FILE]\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38466)  log_msg $2 'Library files must be owned by root.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000046\n\nVulnerability Discussion:  Files from shared library directories are loaded into the address space of processes (including privileged ones) or of the kernel itself at runtime. Proper ownership is necessary to protect the integrity of the system.\n\nFix text: System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default:\n\n/lib\n/lib64\n/usr/lib\n/usr/lib64\n\nIf any file in these directories is found to be owned by a user other than root, correct its ownership with the following command:\n\n#chown root [FILE]\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38469)  log_msg $2 'All system command files must have mode 755 or less permissive.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000047\n\nVulnerability Discussion: System binaries are executed by privileged users, as well as system services, and restrictive permissions are necessary to ensure execution of these programs cannot be co-opted.\n\nFix text: System executables are stored in the following directories by default:\n\n/bin\n/usr/bin\n/usr/local/bin\n/sbin\n/usr/sbin\n/usr/local/sbin\n\nIf any file in these directories is found to be group-writable or world-writable, correct its permission with the following command:\n\n#chmod go-w [FILE]\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38472)  log_msg $2 'All system command files must be owned by root.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000048\n\nVulnerability Discussion: System binaries are executed by privileged users as well as system services, and restrictive permissions are necessary to ensure that their execution of these programs cannot be co-opted.\n\nFix text: System executables are stored in the following directories by default:\n\n/bin\n/usr/bin\n/usr/local/bin\n/sbin\n/usr/sbin\n/usr/local/sbin\n\nIf any file [FILE] in these directories is found to be owned by a user other than root, correct its ownership with the following command:\n\n#chown root [FILE]\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38475)  log_msg $2 'The system must require passwords to contain a minimum of 14 characters.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000025\n\nVulnerability Discussion: Requiring a minimum password length makes password cracking attacks more difficult by ensuring a larger search space. However, any security benefit from an onerous requirement must be carefully weighed against usability problems, support costs, or counterproductive behavior that may result.\n\nWhile it does not negate the password length requirement, it is preferable to migrate from a password-based authentication scheme to a stronger one based on PKI (public key infrastructure).\n\nFix text: To specify password length requirements for new accounts, edit the file "/etc/login.defs" and add or correct the following lines:\n\nPASS_MIN_LEN 14\n\nThe DoD requirement is "14". If a program consults "/etc/login.defs" and also another PAM module (such as"pam_cracklib") during a password change operation, then the most restrictive must be satisfied.\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38477)  log_msg $2 'Users must not be able to change passwords more than once every 24 hours.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000051\n\nVulnerability Discussion: Setting the minimum password age protects against users cycling back to a favorite password after satisfying the password reuse requirement.\n\nFix text: To specify password minimum age for new accounts, edit the file "/etc/login.defs" and add or correct the following line, replacing [DAYS] appropriately:\n\nPASS_MIN_DAYS [DAYS]\n\nA value of 1 day is considered sufficient for many environments. The DoD requirement is 1.\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38479)  log_msg $2 'User passwords must be changed at least every 60 days.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000053\n\nVulnerability Discussion: Setting the password maximum age ensures users are required to periodically change their passwords. This could possibly decrease the utility of a stolen password. Requiring shorter password lifetimes increases the risk of users writing down the password in a convenient location subject to physical compromise.\n\nFix text: To specify password maximum age for new accounts, edit the file "/etc/login.defs" and add or correct the following line, replacing [DAYS] appropriately:\n\nPASS_MAX_DAYS [DAYS]\n\nThe DoD requirement is 60.\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38480)  log_msg $2 'Users must be warned 7 days in advance of password expiration.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000054\n\nVulnerability Discussion: Setting the password warning age enables users to make the change at a practical time.\n\nFix text: To specify how many days prior to password expiration that a warning will be issued to users, edit the file "/etc/login.defs" and add or correct the following line, replacing [DAYS] appropriately:\n\nPASS_WARN_AGE [DAYS]\n\nThe DoD requirement is 7.\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38482)  log_msg $2 'The system must require passwords to contain at least one numeric character.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000056\n\nVulnerability Discussion: Requiring digits makes password guessing attacks more difficult by ensuring a larger search space.\n\nFix text: The pam_cracklib module\047s "dcredit" parameter controls requirements for usage of digits in a password. When set to a negative number, any password will be required to contain that many digits. When set to a positive number, pam_cracklib will grant +1 additional length credit for each digit. Add "dcredit=-1" after pam_cracklib.so to require use of a digit in passwords.  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38569)  log_msg $2 'The system must require passwords to contain at least one uppercase alphabetic character.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000057\n\nVulnerability Discussion: Requiring a minimum number of uppercase characters makes password guessing attacks more difficult by ensuring a larger search space.\n\nFix text: The pam_cracklib module\047s "ucredit=" parameter controls requirements for usage of uppercase letters in a password. When set to a negative number, any password will be required to contain that many uppercase characters. When set to a positive number, pam_cracklib will grant +1 additional length credit for each uppercase character. Add "ucredit=-1" after pam_cracklib.so to require use of an uppercase character in passwords.  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38570)  log_msg $2 'The system must require passwords to contain at least one special character.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000058\n\nVulnerability Discussion: Requiring a minimum number of special characters makes password guessing attacks more difficult by ensuring a larger search space.\n\nFix text:  The pam_cracklib module\047s "ocredit=" parameter controls requirements for usage of special (or ``other'') characters in a password. When set to a negative number, any password will be required to contain that many special characters. When set to a positive number, pam_cracklib will grant +1 additional length credit for each special character. Add "ocredit=-1" after pam_cracklib.so to require use of a special character in passwords.\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38571)  log_msg $2 'The system must require passwords to contain at least one lowercase alphabetic character.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000059\n\nVulnerability Discussion: Requiring a minimum number of lowercase characters makes password guessing attacks more difficult by ensuring a larger search space.\n\nFix text: The pam_cracklib module\047s "lcredit=" parameter controls requirements for usage of lowercase letters in a password. When set to a negative number, any password will be required to contain that many lowercase characters. When set to a positive number, pam_cracklib will grant +1 additional length credit for each lowercase character. Add "lcredit=-1" after pam_cracklib.so to require use of a lowercase character in passwords.  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38572)  log_msg $2 'The system must require at least four characters be changed between the old and new passwords during a password change.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000060\n\nVulnerability Discussion: Requiring a minimum number of different characters during password changes ensures that newly changed passwords should not resemble previously compromised ones. Note that passwords which are changed on compromised systems will still be compromised, however.\n\nFix text: The pam_cracklib module\047s "difok" parameter controls requirements for usage of different characters during a password change. Add "difok=[NUM]" after pam_cracklib.so to require differing characters when changing passwords, substituting [NUM] appropriately. The DoD requirement is 4.  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38573)  log_msg $2 'The system must disable accounts after three consecutive unsuccessful logon attempts.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000061\n\nVulnerability Discussion: Locking out user accounts after a number of incorrect attempts prevents direct password guessing attacks.\n\nFix text: To configure the system to lock out accounts after a number of incorrect logon attempts using\npam_tally2.so\n\nAdd the following lines immediately below the "pam_unix.so" statement in the AUTH section of"/etc/pam.d/common-auth"\n\nauth required pam_tally2.so even_deny_root deny=3 unlock_time=604800 \n\nNote that any updates made to "/etc/pam.d/common-auth" may be overwritten by the "authconfig" program. The "authconfig" program should not be used.  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38574)  log_msg $2 'The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (system-auth).' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000062\n\nVulnerability Discussion: Using a stronger hashing algorithm makes password cracking attacks more difficult.\n\nFix text: In "/etc/pam.d/common-password", among potentially other files, the "password" section of the files control which PAM modules execute during a password change. Set the "pam_unix.so" module in the "password" section to include the argument "sha512", as shown below: \n\npassword sufficient pam_unix.so sha512 [other arguments...]\n\nThis will help ensure when local users change their passwords, hashes for the new passwords will be generated using the SHA-512 algorithm. This is the default.\n\nNote that any updates made to "/etc/pam.d/common-password" will be overwritten by the "authconfig" program. The "authconfig" program should not be used.  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38576)  log_msg $2 'The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (login.defs).' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000063\n\nVulnerability Discussion: Using a stronger hashing algorithm makes password cracking attacks more difficult.\n\nFix text: In "/etc/login.defs", add or correct the following line to ensure the system will use SHA-512 as the hashing algorithm:\n\nENCRYPT_METHOD SHA512\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38577)  log_msg $2 'The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (libuser.conf).' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000064\n\nVulnerability Discussion: Using a stronger hashing algorithm makes password cracking attacks more difficult.\n\nFix text: In "/etc/libuser.conf", add or correct the following line in its "[defaults]" section to ensure the system will use the SHA-512 algorithm for password hashing:\n\ncrypt_style = sha512  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38579)  log_msg $2 'The system boot loader configuration file(s) must be owned by root.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000065\n\nVulnerability Discussion: Only root should be able to modify important boot parameters.\n\nFix text: The file "/boot/grub/grub.cfg" should be owned by the "root" user to prevent destruction or modification of the file. To properly set the owner of "/boot/grub/grub.cfg", run the command:\n\nchown root /boot/grub/grub.cfg\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38581)  log_msg $2 'The system boot loader configuration file(s) must be group-owned by root.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000066\n\nVulnerability Discussion: The "root" group is a highly-privileged group. Furthermore, the group-owner of this file should not have any access privileges anyway.\n\nFix text: The file "/boot/grub/grub.cfg" should be group-owned by the "root" group to prevent destruction or modification of the file. To properly set the group owner of "/boot/grub/grub.cfg", run the command:\n\nchgrp root /boot/grub/grub.cfg\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38583)  log_msg $2 'The system boot loader configuration file(s) must have mode 0600 or less permissive.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000067\n\nVulnerability Discussion: Proper permissions ensure that only the root user can modify important boot parameters.\n\nFix text: File permissions for "/boot/grub/grub.cfg" should be set to 600, which is the default. To properly set the permissions of "/boot/grub/grub.cfg", run the command:\n\n#chmod 600 /boot/grub/grub.cfg\n\nBoot partitions based on VFAT, NTFS, or other non-standard configurations may require alternative measures.\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38585)  log_msg $2 'The system boot loader must require authentication.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000068\n\nVulnerability Discussion: Password protection on the boot loader configuration ensures users with physical access cannot trivially alter important bootloader settings. These include which kernel to use, and whether to enter single-user mode.\n\nFix text: The grub boot loader should have password protection enabled to protect boot-time settings. To do
so, select a password and then generate a hash from it by running the following command:\n\n#grub-mkpasswd-pbkdf2\n\nWhen prompted to enter a password, insert the following line into "/etc/default/grub" immediately after the header comments.And run the following command:\n\n#grub-mkconfig\n\nTo generating configuration file(s)\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38590)  log_msg $2 'The system must allow locking of the console screen in text mode.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000071\n\nVulnerability Discussion: Installing "screen" ensures a console locking capability is available for users who may need to suspend console logins.\n\nFix text: To enable console screen locking when in text mode, install the "screen" package:\n\n#apt-get install screen\n\nInstruct users to begin new terminal sessions with the following command:\n\n$ screen\n\nThe console can now be locked with the following key combination:\n\nctrl+a x\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38596)  log_msg $2 'The system must implement virtual address space randomization.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000078\n\nVulnerability Discussion: Address space layout randomization (ASLR) makes it more difficult for an attacker to predict the location of attack code he or she has introduced into a process\047s address space during
an attempt at exploitation. Additionally, ASLR also makes it more difficult for an attacker to know the location of existing code in order to repurpose it using return oriented programming (ROP) techniques.\n\nFix text: \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38600)  log_msg $2 'The system must not send ICMPv4 redirects by default.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000080\n\nVulnerability Discussion: Sending ICMP redirects permits the system to instruct other systems to update their routing information. The ability to send ICMP redirects is only appropriate for systems acting as routers.\n\nFix text: To set the runtime status of the "net.ipv4.conf.default.send_redirects" kernel parameter, run the following command:\n\n# sysctl -w net.ipv4.conf.default.send_redirects=0\n\nIf this is not the system\047s default value, add the following line to "/etc/sysctl.conf":\n\nnet.ipv4.conf.default.send_redirects = 0  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38601)  log_msg $2 'The system must not send ICMPv4 redirects from any interface.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000081\n\nVulnerability Discussion: Sending ICMP redirects permits the system to instruct other systems to update their routing information. The ability to send ICMP redirects is only appropriate for systems acting as routers.\n\nFix text: \n\nTo set the runtime status of the "net.ipv4.conf.all.send_redirects" kernel parameter, run the following command:\n\n# sysctl -w net.ipv4.conf.all.send_redirects=0\n\nIf this is not the system\047s default value, add the following line to "/etc/sysctl.conf":\n\nnet.ipv4.conf.all.send_redirects = 0\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38511)  log_msg $2 'IP forwarding for IPv4 must not be enabled, unless the system is a router.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000082\n\nVulnerability Discussion: IP forwarding permits the kernel to forward packets from one network interface to another. The ability to forward packets between two networks is only appropriate for systems acting as routers.\n\nFix text: To set the runtime status of the "net.ipv4.ip_forward" kernel parameter, run the following command:\n\n# sysctl -w net.ipv4.ip_forward=0\n\nIf this is not the system\047s default value, add the following line to "/etc/sysctl.conf":\n\nnet.ipv4.ip_forward = 0\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38523)  log_msg $2 'The system must not accept IPv4 source-routed packets on any interface.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000083\n\nVulnerability Discussion: Accepting source-routed packets in the IPv4 protocol has few legitimate uses. It should be disabled unless it is absolutely required.\n\nFix text: To set the runtime status of the "net.ipv4.conf.all.accept_source_route" kernel parameter, run the following command: \n\n# sysctl -w net.ipv4.conf.all.accept_source_route=0\n\nIf this is not the system\047s default value, add the following line to "/etc/sysctl.conf":\n\nnet.ipv4.conf.all.accept_source_route = 0  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38524)  log_msg $2 'The system must not accept ICMPv4 redirect packets on any interface.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000084\n\nVulnerability Discussion: Accepting ICMP redirects has few legitimate uses. It should be disabled unless it is absolutely required.\n\nFix text: To set the runtime status of the "net.ipv4.conf.all.accept_redirects" kernel parameter, run the following command:\n\n# sysctl -w net.ipv4.conf.all.accept_redirects=0\n\nIf this is not the system\047s default value, add the following line to "/etc/sysctl.conf":\n\nnet.ipv4.conf.all.accept_redirects = 0  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38526)  log_msg $2 'The system must not accept ICMPv4 secure redirect packets on any interface.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000086\n\nVulnerability Discussion: Accepting "secure" ICMP redirects (from those gateways listed as default gateways) has few legitimate uses. It should be disabled unless it is absolutely required.\n\nFix text: To set the runtime status of the "net.ipv4.conf.all.secure_redirects" kernel parameter, run the following command:\n\n# sysctl -w  net.ipv4.conf.all.secure_redirects=0\n\nIf this is not the system\047s default value, add the following line to "/etc/sysctl.conf":\n\nnet.ipv4.conf.all.secure_redirects = 0  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38528)  log_msg $2 'The system must log Martian packets.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000088\n\nVulnerability Discussion: The presence of "martian" packets (which have impossible addresses) as well asspoofed packets, source-routed packets, and redirects could be a sign of nefarious network activity. Logging these packets enables this activity to be detected.\n\nFix text: To set the runtime status of the "net.ipv4.conf.all.log_martians" kernel parameter, run the following command:\n\n# sysctl -w net.ipv4.conf.all.log_martians=1\n\nIf this is not the system\047s default value, add the following line to "/etc/sysctl.conf":\n\nnet.ipv4.conf.all.log_martians = 1\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38529)  log_msg $2 'The system must not accept IPv4 source-routed packets by default.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000089\n\nVulnerability Discussion: Accepting source-routed packets in the IPv4 protocol has few legitimate uses. It should be disabled unless it is absolutely required.\n\nFix text: To set the runtime status of the "net.ipv4.conf.default.accept_source_route" kernel parameter, run the following command:\n\n# sysctl -w net.ipv4.conf.default.accept_source_route=0\n\nIf this is not the system\047s default value, add the following line to "/etc/sysctl.conf":\n\nnet.ipv4.conf.default.accept_source_route = 0  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38532)  log_msg $2 'The system must not accept ICMPv4 secure redirect packets by default.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000090\n\nVulnerability Discussion: Accepting "secure" ICMP redirects (from those gateways listed as default gateways) has few legitimate uses. It should be disabled unless it is absolutely required.\n\nFix text: To set the runtime status of the "net.ipv4.conf.default.secure_redirects" kernel parameter, run the following command:\n\n# sysctl -w net.ipv4.conf.default.secure_redirects=0\n\nIf this is not the system\047s default value, add the following line to "/etc/sysctl.conf":\n\nnet.ipv4.conf.default.secure_redirects = 0\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38533)  log_msg $2 'The system must ignore ICMPv4 redirect messages by default.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000091\n\nVulnerability Discussion: This feature of the IPv4 protocol has few legitimate uses. It should be disabled unless it is absolutely required.\n\nFix text: To set the runtime status of the "net.ipv4.conf.default.accept_redirects" kernel parameter, run the following command:\n\n# sysctl -w net.ipv4.conf.default.accept_redirects=0\n\nIf this is not the system\047s default value, add the following line to "/etc/sysctl.conf":\n\nnet.ipv4.conf.default.accept_redirects = 0  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38535)  log_msg $2 'The system must not respond to ICMPv4 sent to a broadcast address.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000092\n\nVulnerability Discussion: The system must not respond to ICMPv4 sent to a broadcast address.\n\nFix text: Ignoring ICMP echo requests (pings) sent to broadcast or multicast addresses makes the system slightly more difficult to enumerate on the network.\n\nTo set the runtime status of the "net.ipv4.icmp_echo_ignore_broadcasts" kernel parameter, run the following command:\n\n# sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1\n\nIf this is not the system\047s default value, add the following line to "/etc/sysctl.conf":\n\nnet.ipv4.icmp_echo_ignore_broadcasts = 1  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38537)  log_msg $2 'The system must ignore ICMPv4 bogus error responses.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000093\n\nVulnerability Discussion: Ignoring bogus ICMP error responses reduces log size, although some activity would not be logged.\n\nFix text: To set the runtime status of the "net.ipv4.icmp_ignore_bogus_error_responses" kernel parameter, run the following command:\n\n# sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1\n\nIf this is not the system\047s default value, add the following line to "/etc/sysctl.conf":\n\nnet.ipv4.icmp_ignore_bogus_error_responses = 1  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38539)  log_msg $2 'The system must be configured to use TCP syncookies when experiencing a TCP SYN flood.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000095\n\nVulnerability Discussion: A TCP SYN flood attack can cause a denial of service by filling a system\047s TCP connection table with connections in the SYN_RCVD state. Syncookies can be used to track a connection when a subsequent ACK is received, verifying the initiator is attempting a valid connection and is not a flood source. This feature is activated when a flood condition is detected, and enables the system to continue servicing valid connection requests.\n\nFix text: To set the runtime status of the "net.ipv4.tcp_syncookies" kernel parameter, run the following command:\n\n# sysctl -w net.ipv4.tcp_syncookies=1\n\nIf this is not the system\047s default value, add the following line to "/etc/sysctl.conf":\n\nnet.ipv4.tcp_syncookies = 1  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38542)  log_msg $2 'The system must use a reverse-path filter for IPv4 network traffic when possible on all interfaces.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000096\n\nVulnerability Discussion: Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface they were received on. It should not be used on systems which are routers for complicated networks, but is helpful for end hosts and routers serving small networks.\n\nFix text: To set the runtime status of the "net.ipv4.conf.all.rp_filter" kernel parameter, run the following command:\n\n# sysctl -w net.ipv4.conf.all.rp_filter=1\n\nIf this is not the system\047s default value, add the following line to "/etc/sysctl.conf":\n\nnet.ipv4.conf.all.rp_filter = 1\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38544)  log_msg $2 'The system must use a reverse-path filter for IPv4 network traffic when possible by default.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000097\n\nVulnerability Discussion: Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface they were received on. It should not be used on systems which are routers for complicated networks, but is helpful for end hosts and routers serving small networks.\n\nFix text: To set the runtime status of the "net.ipv4.conf.default.rp_filter" kernel parameter, run the following command:\n\n# sysctl -w net.ipv4.conf.default.rp_filter=1\n\nIf this is not the system\047s default value, add the following line to "/etc/sysctl.conf":\n\nnet.ipv4.conf.default.rp_filter = 1\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38546)  log_msg $2 'The IPv6 protocol handler must not be bound to the network stack unless needed.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000098\n\nVulnerability Discussion: Any unnecessary network stacks - including IPv6 - should be disabled, to reduce the vulnerability to exploitation.\n\nFix text: To disable IPv6 networking stack ,add the following line to "/etc/default/grub"\n\nFind the line that contain "GRUB_CMDLINE_LINUX_DEFAULT":\n\nGRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
\n\nAdd "ipv6.disable=1" to the boot option, then save your grub file:\n\nGRUB_CMDLINE_LINUX_DEFAULT="ipv6.disable=1 quiet splash"\n\nsudo update-grub\n\nFor more details You could visit:http://askubuntu.com/questions/309461/how-to-disable-ipv6-permanently\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38548)  log_msg $2 'The system must ignore ICMPv6 redirects by default.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000099\n\nVulnerability Discussion: An illicit ICMP redirect message could result in a man-in-the-middle attack.\n\nFix text: To set the runtime status of the "net.ipv6.conf.default.accept_redirects" kernel parameter, run the following command:\n\n# sysctl -w net.ipv6.conf.default.accept_redirects=0\n\nIf this is not the system\047s default value, add the following line to "/etc/sysctl.conf":\n\nnet.ipv6.conf.default.accept_redirects = 0\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38513)  log_msg $2 'The systems local IPv4 firewall must implement a deny-all, allow-by-exception policy for inbound packets.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000120\n\nVulnerability Discussion: In "iptables" the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to "DROP" implements proper design for a firewall, i.e., any packets which are not explicitly permitted should not be accepted.\n\nFix text: To set the default policy to DROP (instead of ACCEPT) for the built-in INPUT chain which processes incoming packets, you could use following command:\n\n#iptables -P INPUT DROP\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38514)  log_msg $2 'The Datagram Congestion Control Protocol (DCCP) must be disabled unless required.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000124\n\nVulnerability Discussion: Disabling DCCP protects the system against exploitation of any flaws in its implementation.\n\nFix text: The Datagram Congestion Control Protocol (DCCP) is a relatively new transport layer protocol, designed to support streaming media and telephony. To configure the system to prevent the "dccp" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d":\n\ninstall dccp /bin/true\n\n######################\n\n' >> $LOG
              fi   
              ;;
    V-38515)  log_msg $2 'The Stream Control Transmission Protocol (SCTP) must be disabled unless required.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000125\n\nVulnerability Discussion: Disabling SCTP protects the system against exploitation of any flaws in its implementation.\n\nFix text: The Stream Control Transmission Protocol (SCTP) is a transport layer protocol, designed to support the idea of message-oriented communication, with several streams of messages within one connection. To configure the system to prevent the "sctp" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d":\n\ninstall sctp /bin/true  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38516)  log_msg $2 'The Reliable Datagram Sockets (RDS) protocol must be disabled unless required.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000126\n\nVulnerability Discussion: \n\nFix text: Disabling RDS protects the system against exploitation of any flaws in its implementation.\n\nThe Reliable Datagram Sockets (RDS) protocol is a transport layer protocol designed to provide reliable high-bandwidth, low-latency communications between nodes in a cluster. To configure the system to prevent the "rds" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d":\n\ninstall rds /bin/true  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38517)  log_msg $2 'The Transparent Inter-Process Communication (TIPC) protocol must be disabled unless required.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000127\n\nVulnerability Discussion: Disabling TIPC protects the system against exploitation of any flaws in its implementation.\n\nFix text: The Transparent Inter-Process Communication (TIPC) protocol is designed to provide communications between nodes in a cluster. To configure the system to prevent the "tipc" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d":\n\ninstall tipc /bin/true  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38518)  log_msg $2 'All rsyslog-generated log files must be owned by root.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000133\n\nVulnerability Discussion: The log files generated by rsyslog contain valuable information regarding system configuration, user authentication, and other such information. Log files should be protected from unauthorized access.\n\nFix text: The owner of all log files written by "rsyslog" should be root. These log files are determined by the second part of each Rule line in "/etc/rsyslog.conf" typically all appear in "/var/log". For each log file [LOGFILE] referenced in "/etc/rsyslog.conf", run the following command to inspect the file\047s owner:\n\n$ ls -l [LOGFILE]\n\nIf the owner is not "root", run the following command to correct this:\n\n# chown root [LOGFILE]\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38519)  log_msg $2 'All rsyslog-generated log files must be group-owned by root.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000134\n\nVulnerability Discussion: The log files generated by rsyslog contain valuable information regarding system configuration, user authentication, and other such information. Log files should be protected from unauthorized access.\n\nFix text: The group-owner of all log files written by "rsyslog" should be root. These log files are determined by the second part of each Rule line in "/etc/rsyslog.conf" and typically all appear in "/var/log". For each log file [LOGFILE] referenced in "/etc/rsyslog.conf", run the following command to inspect the file\047s group owner:\n\n$ ls -l [LOGFILE]\n\nIf the owner is not "root", run the following command to correct this:\n\n# chgrp root [LOGFILE]\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38623)  log_msg $2 'All rsyslog-generated log files must have mode 0600 or less permissive.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000135\n\nVulnerability Discussion: Log files can contain valuable information regarding system configuration. If the system log files are not protected, unauthorized users could change the logged data, eliminating their forensic value.\n\nFix text: The file permissions for all log files written by rsyslog should be set to 600, or more restrictive. These log files are determined by the second part of each Rule line in "/etc/rsyslog.conf" and typically all appear in "/var/log". For each log file [LOGFILE] referenced in "/etc/rsyslog.conf", run the following command to inspect the file\047s permissions:\n\n$ ls -l [LOGFILE]\n\nIf the permissions are not 600 or more restrictive, run the following command to correct this:\n\n# chmod 0600 [LOGFILE]  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38520)  log_msg $2 'The operating system must back up audit records on an organization defined frequency onto a different system or media than the system being audited.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000136\n\nVulnerability Discussion: A log server (loghost) receives syslog messages from one or more systems. This data can be used as an additional log source in the event a system is compromised and its local logs are suspect. Forwarding log messages to a remote loghost also provides system administrators with a centralized place to view the status of multiple hosts within the enterprise.\n\nFix text: To configure rsyslog to send logs to a remote log server, open "/etc/rsyslog.conf" and read and understand the last section of the file, which describes the multiple directives necessary to activate remote logging. Along with these other directives, the system can be configured to forward its logs to a particular log server by adding or correcting one of the following lines, substituting "[loghost.example.com]" appropriately. The choice of protocol depends on the environment of the system; although TCP and RELP provide more reliable message delivery, they may not be supported in all environments.\nTo use UDP for log message delivery:\n\n*.* @[loghost.example.com]\n\nTo use TCP for log message delivery:\n\n*.* @@[loghost.example.com]\n\nTo use RELP for log message delivery:\n\n*.* :omrelp:[loghost.example.com]  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38521)  log_msg $2 'The operating system must support the requirement to centrally manage the content of audit records generated by organization defined information system components.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000137\n\nVulnerability Discussion: A log server (loghost) receives syslog messages from one or more systems. This data can be used as an additional log source in the event a system is compromised and its local logs are suspect. Forwarding log messages to a remote loghost also provides system administrators with a centralized place to view the status of multiple hosts within the enterprise.\n\nFix text: To configure rsyslog to send logs to a remote log server, open "/etc/rsyslog.conf" and read and understand the last section of the file, which describes the multiple directives necessary to activate remote logging. Along with these other directives, the system can be configured to forward its logs to a particular log server by adding or correcting one of the following lines, substituting "[loghost.example.com]" appropriately. The choice of protocol depends on the environment of the system; although TCP and RELP provide more reliable message delivery, they may not be supported in all environments.\nTo use UDP for log message delivery:\n\n*.* @[loghost.example.com]\n\nTo use TCP for log message delivery:\n\n*.* @@[loghost.example.com]\n\nTo use RELP for log message delivery:\n\n*.* :omrelp:[loghost.example.com]  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38624)  log_msg $2 'System logs must be rotated daily.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000138\n\nVulnerability Discussion: Log files that are not properly rotated run the risk of growing so large that they fill up the /var/log partition. Valuable logging information could be lost if the /var/log  partition becomes full.\n\nFix text: The "logrotate" service should be installed or reinstalled if it is not installed and operating properly, by running the following command:\n\n#apt-get install logrotate\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38628)  log_msg $2 'The operating system must produce audit records containing sufficient information to establish the identity of any user/subject associated with the event.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000145\n\nVulnerability Discussion: Ensuring the "auditd" service is active ensures audit records generated by the kernel can be written to disk, or that appropriate actions will be taken if other obstacles exist.\n\nFix text: The "auditd" service is an essential userspace component of the Linux Auditing System, as it is responsible for writing audit records to disk. The "auditd" service can be enabled with the following commands:\n\n#update-rc.d auditd defaults\n# service auditd start  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38631)  log_msg $2 'The operating system must employ automated mechanisms to facilitate the monitoring and control of remote access methods.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000148\n\nVulnerability Discussion: The operating system must employ automated mechanisms to facilitate the monitoring and control of remote access methods.\n\nFix text: The "auditd" service is an essential userspace component of the Linux Auditing System, as it is responsible for writing audit records to disk. The "auditd" service can be enabled with the following commands:\n\n#update-rc.d auditd defaults\n# service auditd start  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38632)  log_msg $2 'The operating system must produce audit records containing sufficient information to establish what type of events occurred.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000154\n\nVulnerability Discussion: Ensuring the "auditd" service is active ensures audit records generated by the kernel can be written to disk, or that appropriate actions will be taken if other obstacles exist.\n\nFix text: The "auditd" service is an essential userspace component of the Linux Auditing System, as it is responsible for writing audit records to disk. The "auditd" service can be enabled with the following commands:\n\n#update-rc.d auditd defaults\n# service auditd start  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38636)  log_msg $2 'The system must retain enough rotated audit logs to cover the required log retention period.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000159\n\nVulnerability Discussion: The total storage for audit log files must be large enough to retain log information over the period required. This is a function of the maximum log file size and the number of logs retained.\n\nFix text: Determine how many log files "auditd" should retain when it rotates logs. Edit the file "/etc/audit/auditd.conf". Add or modify the following line, substituting [NUMLOGS] with the correct value:\n\nnum_logs = [NUMLOGS]\n\nSet the value to 5 for general-purpose systems. Note that values less than 2 result in no log rotation.\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38633)  log_msg $2 'The system must set a maximum audit log file size.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000160\n\nVulnerability Discussion: The total storage for audit log files must be large enough to retain log information over the period required. This is a function of the maximum log file size and the number of logs retained.\n\nFix text: Determine the amount of audit data (in megabytes) which should be retained in each log file. Edit the file "/etc/audit/auditd.conf". Add or modify the following line, substituting the correct value for [STOREMB]:\n\nmax_log_file = [STOREMB]Set the value to "6" (MB) or higher for general-purpose systems. Larger values, of course, support retention of even more audit data.  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38634)  log_msg $2 'The system must rotate audit log files that reach the maximum file size.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000161\n\nVulnerability Discussion: Automatically rotating logs (by setting this to "rotate") minimizes the chances of the system unexpectedly running out of disk space by being overwhelmed with log data. However, for systems that must never discard log data, or which use external processes to transfer it and reclaim space, "keep_logs" can be employed.\n\nFix text: The default action to take when the logs reach their maximum size is to rotate the log files, discarding the oldest one. To configure the action taken by "auditd", add or correct the line in "/etc/audit/auditd.conf":\n\nmax_log_file_action = [ACTION]\n\nPossible values for [ACTION] are described in the "auditd.conf" man page. These include:\n\n"ignore"\n"syslog"\n"suspend"\n"rotate"\n"keep_logs"\n\nSet the "[ACTION]" to "rotate" to ensure log rotation occurs. This is the default. The setting is case-insensitive.  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-54381)  log_msg $2 'The audit system must switch the system to single-user mode when available audit storage volume becomes dangerously low.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000163\n\nVulnerability Discussion: Administrators should be made aware of an inability to record audit records. If a separate partition or logical volume of adequate size is used, running low on space for audit records should never occur.\n\nFix text: The "auditd" service can be configured to take an action when disk space is running low but prior to running out of space completely. Edit the file "/etc/audit/auditd.conf". Add or modify the following line, substituting [ACTION] appropriately:\n\nadmin_space_left_action = [ACTION]\n\nSet this value to "single" to cause the system to switch to single-user mode for corrective action. Acceptable values also include "suspend" and "halt". For certain systems, the need for availability outweighs the need to log all actions, and a different setting should be determined. Details regarding all possible values for [ACTION] are described in the "auditd.conf" man page.  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38635)  log_msg $2 'The audit system must be configured to audit all attempts to alter system time through adjtimex.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000165\n\nVulnerability Discussion: Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.\n\nFix text: On a 32-bit system, add the following to \"/etc/audit/audit.rules\": \n\n# audit_time_rules\n-a always,exit -F arch=b32 -S adjtimex -k audit_time_rules\n\nOn a 64-bit system, add the following to \"/etc/audit/audit.rules\": \n\n# audit_time_rules\n-a always,exit -F arch=b64 -S adjtimex -k audit_time_rules\n\nThe -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport. Multiple system calls can be defined on the same line to save space if desired, but is not required. See an example of multiple combined syscalls: \n\n-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38522)  log_msg $2 'The audit system must be configured to audit all attempts to alter system time through settimeofday.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000167\n\nVulnerability Discussion: Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.\n\nFix text: On a 32-bit system, add the following to \"/etc/audit/audit.rules\": \n\n# audit_time_rules\n-a always,exit -F arch=b32 -S settimeofday -k audit_time_rules\n\nOn a 64-bit system, add the following to \"/etc/audit/audit.rules\": \n\n# audit_time_rules\n-a always,exit -F arch=b64 -S settimeofday -k audit_time_rules\n\nThe -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport. Multiple system calls can be defined on the same line to save space if desired, but is not required. See an example of multiple combined syscalls: \n\n-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38525)  log_msg $2 'The audit system must be configured to audit all attempts to alter system time through stime.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000169\n\nVulnerability Discussion: Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.\n\nFix text: On a 32-bit system, add the following to \"/etc/audit/audit.rules\": \n\n# audit_time_rules\n-a always,exit -F arch=b32 -S stime -k audit_time_rules\n\nOn a 64-bit system, the \"-S stime\" is not necessary. The -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport. Multiple system calls can be defined on the same line to save space if desired, but is not required. See an example of multiple combined syscalls: \n\n-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38527)  log_msg $2 'The audit system must be configured to audit all attempts to alter system time through clock_settime.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000171\n\nVulnerability Discussion: Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an  accurate system time (such as sshd). All changes to the system time should be audited.\n\nFix text: On a 32-bit system, add the following to "/etc/audit/audit.rules":\n\n# audit_time_rules\n-a always,exit -F arch=b32 -S clock_settime -k audit_time_rules\n\nOn a 64-bit system, add the following to "/etc/audit/audit.rules":\n\n# audit_time_rules\n\n-a always,exit -F arch=b64 -S clock_settime -k audit_time_rules\n\nThe -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport. Multiple system calls can be defined on the same line to save space if desired, but is not required. See an example of multiple combined syscalls:\n\n-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38530)  log_msg $2 'The audit system must be configured to audit all attempts to alter system time through /etc/localtime.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000173\n\nVulnerability Discussion: Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.\n\nFix text: Add the following to "/etc/audit/audit.rules":\n\n-w /etc/localtime -p wa -k audit_time_rules\n\nThe -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport and should always be used.\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38531)  log_msg $2 'The operating system must automatically audit account creation.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000174\n\nVulnerability Discussion: In addition to auditing new user and group accounts, these watches will alert the 
system administrator(s) to any modifications. Any unexpected users, groups, or modifications should be investigated for legitimacy.\n\nFix text: Add the following to "/etc/audit/audit.rules", in order to capture events that modify account changes:\n\n# audit_account_changes\n-w /etc/group -p wa -k audit_account_changes\n-w /etc/passwd -p wa -k audit_account_changes\n-w /etc/gshadow -p wa -k audit_account_changes\n-w /etc/shadow -p wa -k audit_account_changes\n-w /etc/security/opasswd -p wa -k audit_account_changes\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38534)  log_msg $2 'The operating system must automatically audit account modification.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000175\n\nVulnerability Discussion: In addition to auditing new user and group accounts, these watches will alert the system administrator(s) to any modifications. Any unexpected users, groups, or modifications should be investigated for legitimacy.\n\nFix text: Add the following to "/etc/audit/audit.rules", in order to capture events that modify account changes:\n\n# audit_account_changes\n-w /etc/group -p wa -k audit_account_changes\n-w /etc/passwd -p wa -k audit_account_changes\n-w /etc/gshadow -p wa -k audit_account_changes\n-w /etc/shadow -p wa -k audit_account_changes-w /etc/security/opasswd -p wa -k audit_account_changes\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38536)  log_msg $2 'The operating system must automatically audit account disabling actions.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000176\n\nVulnerability Discussion:  In addition to auditing new user and group accounts, these watches will alert the system administrator(s) to any modifications. Any unexpected users, groups, or modifications should be investigated for legitimacy.\n\nFix text: Add the following to "/etc/audit/audit.rules", in order to capture events that modify account changes:\n\n#audit_account_changes\n-w /etc/group -p wa -k audit_account_changes\n-w /etc/passwd -p wa -k audit_account_changes\n-w /etc/gshadow -p wa -k audit_account_changes\n-w /etc/shadow -p wa -k audit_account_changes\n-w /etc/security/opasswd -p wa -k audit_account_changes\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38538)  log_msg $2 'The operating system must automatically audit account termination.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000177\n\nVulnerability Discussion: In addition to auditing new user and group accounts, these watches will alert the system administrator(s) to any modifications. Any unexpected users, groups, or modifications should be investigated for legitimacy.\n\nFix text: Add the following to "/etc/audit/audit.rules", in order to capture events that modify account changes:\n\n#audit_account_changes\n-w /etc/group -p wa -k audit_account_changes\n-w /etc/passwd -p wa -k audit_account_changes\n-w /etc/gshadow -p wa -k audit_account_changes\n-w /etc/shadow -p wa -k audit_account_changes\n-w /etc/security/opasswd -p wa -k audit_account_changes\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38540)  log_msg $2 'The audit system must be configured to audit modifications to the systems network configuration.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000182\n\nVulnerability Discussion: The network environment should not be modified by anything other than administrator action. Any change to network parameters should be audited.\n\nFix text: Add the following to "/etc/audit/audit.rules", setting ARCH to either b32 or b64 as appropriate for your system:\n\n# audit_network_modifications\n-a always,exit -F arch=ARCH -S sethostname -S setdomainname -k audit_network_modifications\n-w /etc/issue -p wa -k audit_network_modifications\n-w /etc/issue.net -p wa -k audit_network_modifications\n-w /etc/hosts -p wa -k audit_network_modifications\n-w /etc/sysconfig/network -p wa -k audit_network_modifications  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38541)  log_msg $2 'The audit system must be configured audit modifications to the systems Mandatory Access Control (MAC) configuration (Apparmor).' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000183\n\nVulnerability Discussion: The system\047s mandatory access policy (Apparmor) should not be arbitrarily changed by anything other than administrator action. All changes to MAC policy should be audited.\n\nFix text: Add the following to "/etc/audit/audit.rules":\n\n-w /etc/apparmor/ -p wa -k apparmor\n-w /etc/apparmor.d/ -p wa -k apparmor\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38543)  log_msg $2 'The audit system must be configured to audit all discretionary access control permission modifications using chmod.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000184\n\nVulnerability Discussion: The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.\n\nFix text: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules":\n\n-a always,exit -F arch=b32 -S chmod -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S chmod -F auid=0 -k perm_mod\n\nIf the system is 64-bit, then also add the following:-a always,exit -F arch=b64 -S chmod -F auid>=500 -F auid!=4294967295 -k perm_mod \n-a always,exit -F arch=b64 -S chmod -F auid=0 -k perm_mod  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38545)  log_msg $2 'The audit system must be configured to audit all discretionary access control permission modifications using chown.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000185\n\nVulnerability Discussion: The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.\n\nFix text: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules":\n\n-a always,exit -F arch=b32 -S chown -F auid>=500 -F auid!=4294967295 -k perm_mod\n\n-a always,exit -F arch=b32 -S chown -F auid=0 -k perm_mod\n\nIf the system is 64-bit, then also add the following:\n\n-a always,exit -F arch=b64 -S chown -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b64 -S chown -F auid=0 -k perm_mod \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38547)  log_msg $2 'The audit system must be configured to audit all discretionary access control permission modifications using fchmod.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000186\n\nVulnerability Discussion: The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.\n\nFix text: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules":\n\n-a always,exit -F arch=b32 -S fchmod -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S fchmod -F auid=0 -k perm_mod\n\nIf the system is 64-bit, then also add the following:\n\n-a always,exit -F arch=b64 -S fchmod -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b64 -S fchmod -F auid=0 -k perm_mod\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38550)  log_msg $2 'The audit system must be configured to audit all discretionary access control permission modifications using fchmodat.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000187\n\nVulnerability Discussion: The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.\n\nFix text: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules":\n\n-a always,exit -F arch=b32 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S fchmodat -F auid=0 -k perm_mod\n\nIf the system is 64-bit, then also add the following:\n\n-a always,exit -F arch=b64 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b64 -S fchmodat -F auid=0 -k perm_mod  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38552)  log_msg $2 'The audit system must be configured to audit all discretionary access control permission modifications using fchown.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000188\n\nVulnerability Discussion: The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.\n\nFix text: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules":\n\n-a always,exit -F arch=b32 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S fchown -F auid=0 -k perm_mod\n\nIf the system is 64-bit, then also add the following:-a always,exit -F arch=b64 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b64 -S fchown -F auid=0 -k perm_mod  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38554)  log_msg $2 ' The audit system must be configured to audit all discretionary access control permission modifications using fchownat.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000189\n\nVulnerability Discussion: The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users\n\nFix text: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules":\n\n-a always,exit -F arch=b32 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S fchownat -F auid=0 -k perm_mod\n\nIf the system is 64-bit, then also add the following:\n\n-a always,exit -F arch=b64 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b64 -S fchownat -F auid=0 -k perm_mod\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38556)  log_msg $2 'The audit system must be configured to audit all discretionary access control permission modifications using fremovexattr.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID: RHEL-06-000190\n\nVulnerability Discussion: The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.\n\nFix text: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules":\n\n-a always,exit -F arch=b32 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod \n-a always,exit -F arch=b32 -S fremovexattr -F auid=0 -k perm_mod\n\nIf the system is 64-bit, then also add the following:\n\n-a always,exit -F arch=b64 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b64 -S fremovexattr -F auid=0 -k perm_mod\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38557)  log_msg $2 'The audit system must be configured to audit all discretionary access control permission modifications using fsetxattr.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000191\n\nVulnerability Discussion: The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.\n\nFix text: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules":\n\n-a always,exit -F arch=b32 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S fsetxattr -F auid=0 -k perm_mod\n\nIf the system is 64-bit, then also add the following:\n\n-a always,exit -F arch=b64 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b64 -S fsetxattr -F auid=0 -k perm_mod\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38558)  log_msg $2 'The audit system must be configured to audit all discretionary access control permission modifications using lchown.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-0001920\n\nVulnerability Discussion: The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.\n\nFix text: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules":\n\n-a always,exit -F arch=b32 -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S lchown -F auid=0 -k perm_mod\n\nIf the system is 64-bit, then also add the following:\n\n-a always,exit -F arch=b64 -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b64 -S lchown -F auid=0 -k perm_mod\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38559)  log_msg $2 'The audit system must be configured to audit all discretionary access control permission modifications using lremovexattr.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000193\n\nVulnerability Discussion: The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.\n\nFix text: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules":\n\n-a always,exit -F arch=b32 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S lremovexattr -F auid=0 -k perm_mod\n\nIf the system is 64-bit, then also add the following:\n\n-a always,exit -F arch=b64 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b64 -S lremovexattr -F auid=0 -k perm_mod\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38561)  log_msg $2 'The audit system must be configured to audit all discretionary access control permission modifications using lsetxattr.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000194\n\nVulnerability Discussion: The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.\n\nFix text: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules":\n\n-a always,exit -F arch=b32 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod \n-a always,exit -F arch=b32 -S lsetxattr -F auid=0 -k perm_mod\n\nIf the system is 64-bit, then also add the following:\n\n-a always,exit -F arch=b64 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b64 -S lsetxattr -F auid=0 -k perm_mod\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38563)  log_msg $2 'The audit system must be configured to audit all discretionary access control permission modifications using removexattr.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000195\n\nVulnerability Discussion: The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.\n\nFix text: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules":\n\n-a always,exit -F arch=b32 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S removexattr -F auid=0 -k perm_mod\n\nIf the system is 64-bit, then also add the following:\n\n-a always,exit -F arch=b64 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b64 -S removexattr -F auid=0 -k perm_mod\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38565)  log_msg $2 'The audit system must be configured to audit all discretionary access control permission modifications using setxattr.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000196\n\nVulnerability Discussion: The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate theidentification of patterns of abuse among both authorized and unauthorized users.\n\nFix text: At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules":\n\n-a always,exit -F arch=b32 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S setxattr -F auid=0 -k perm_mod\n\nIf the system is 64-bit, then also add the following:\n\n-a always,exit -F arch=b64 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod \n-a always,exit -F arch=b64 -S setxattr -F auid=0 -k perm_mod\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38566)  log_msg $2 'The audit system must be configured to audit failed attempts to access files and programs.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000197\n\nVulnerability Discussion: Unsuccessful attempts to access files could be an indicator of malicious activity on a system. Auditing these events could serve as evidence of potential system compromise.\n\nFix text: At a minimum, the audit system should collect unauthorized file accesses for all users and root. Add the following to "/etc/audit/audit.rules", setting ARCH to either b32 or b64 as appropriate for your system:\n\n-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \\\n-S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access\n-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \\\n-S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access\n-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \\\n-S ftruncate -F exit=-EACCES -F auid=0 -k access\n-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \\\n -S ftruncate -F exit=-EPERM -F auid=0 -k access  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38567)  log_msg $2 'The audit system must be configured to audit all use of setuid and setgid programs.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000198\n\nVulnerability Discussion: Privileged programs are subject to escalation-of-privilege attacks, which attempt to subvert their normal role of providing some necessary but limited capability. As such, motivation exists to monitor these programs for unusual activity.\n\nFix text: At a minimum, the audit system should collect the execution of privileged commands for all users and root. To find the relevant setuid / setgid programs, run the following command for each local partition [PART]:\n\n$ sudo find [PART] -xdev -type f -perm /6000 2>/dev/null\n\nThen, for each setuid / setgid program on the system, add a line of the following form to "/etc/audit/audit.rules", where [SETUID_PROG_PATH] is the full path to each setuid / setgid program in the list:\n\n-a always,exit -F path=[SETUID_PROG_PATH] -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38568)  log_msg $2 'The audit system must be configured to audit successful file system mounts.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000199\n\nVulnerability Discussion: The unauthorized exportation of data to external media could result in an information leak where classified information, Privacy Act information, and intellectual property could be lost. An audit trail should be created each time a filesystem is mounted to help identify and guard against information loss.\n\nFix text: At a minimum, the audit system should collect media exportation events for all users and root. Add the following to "/etc/audit/audit.rules", setting ARCH to either b32 or b64 as appropriate for your system:\n\n-a always,exit -F arch=ARCH -S mount -F auid>=500 -F auid!=4294967295 -k export\n-a always,exit -F arch=ARCH -S mount -F auid=0 -k export  \n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38575)  log_msg $2 'The audit system must be configured to audit user deletions of files and programs.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000200\n\nVulnerability Discussion: Auditing file deletions will create an audit trail for files that are removed from the system. The audit trail could aid in system troubleshooting, as well as detecting malicious processes that attempt to delete log files to conceal their presence.\n\nFix text: \n\nAt a minimum, the audit system should collect file deletion events for all users and root. Add the following (or equivalent) to "/etc/audit/audit.rules", setting ARCH to either b32 or b64 as appropriate for your system:\n\n-a always,exit -F arch=ARCH -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete\n-a always,exit -F arch=ARCH -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid=0 -k delete\n\n######################\n\n' >> $LOG
              fi
              ;;
    V-38578)  log_msg $2 'The audit system must be configured to audit changes to the /etc/sudoers file.' 
              if [ $2 -ne 0 ];then 
                  printf '\n######################\n\nSTIG-ID:RHEL-06-000201\n\nVulnerability Discussion: The actions taken by system administrators should be audited to keep a record of what was executed on the system, as well as, for accountability purposes.\n\nFix text: At a minimum, the audit system should collect administrator actions for all users and root. Add the following to "/etc/audit/audit.rules":\n-w /etc/sudoers -p wa -k actions\n\n######################\n\n' >> $LOG
              fi
              ;;

    esac
}

