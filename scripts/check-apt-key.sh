#!/bin/bash
#Verify with the key fatch from https://ftp-master.debian.org/keys.html

#---------------------------------------------------------------------------
#"Debian Archive Automatic Signing Key (8/jessie) <ftpmaster@debian.org>"

JESSIEARCHIVEKEY=" 126C 0D24 BD8A 2942 CC7D  F8AC 7638 D044 2B90 D010"
CHECKTMP=$(apt-key finger | grep -B 1 "Debian Archive Automatic Signing Key (8/jessie) <ftpmaster@debian.org>" | head -n1 | awk -F '=' '{printf $2}')

if [ "$CHECKTMP" == "$JESSIEARCHIVEKEY" ];then
       echo Good
       :
else
       echo bad
       exit 1
fi

#---------------------------------------------------------------------------
#"Debian Security Archive Automatic Signing Key (8/jessie) <ftpmaster@debian.org>"

JESSIESECURITYKEY=" D211 6914 1CEC D440 F2EB  8DDA 9D6D 8F6B C857 C906"
CHECKTMP=$(apt-key finger | grep -B 1 "Debian Security Archive Automatic Signing Key (8/jessie) <ftpmaster@debian.org>" | head -n1 | awk -F '=' '{printf $2}')

if [ "$CHECKTMP" == "$JESSIESECURITYKEY" ];then
       echo Good
       :
else
       echo bad
       exit 1
fi

#---------------------------------------------------------------------------
#"Jessie Stable Release Key <debian-release@lists.debian.org>"

JESSIESTABLEKEY=" 75DD C3C4 A499 F1A1 8CB5  F3C8 CBF8 D6FD 518E 17E1"
CHECKTMP=$(apt-key finger | grep -B 1 "Jessie Stable Release Key <debian-release@lists.debian.org>" | head -n1 | awk -F '=' '{printf $2}')

if [ "$CHECKTMP" == "$JESSIESTABLEKEY" ];then
       echo Good
       :
else
       echo bad
       exit 1
fi

#---------------------------------------------------------------------------
#"Debian Archive Automatic Signing Key (6.0/squeeze) <ftpmaster@debian.org>"

SQUEEZEARCHIVEKEY=" 9FED 2BCB DCD2 9CDF 7626  78CB AED4 B06F 4730 41FA"
CHECKTMP=$(apt-key finger | grep -B 1 "Debian Archive Automatic Signing Key (6.0/squeeze) <ftpmaster@debian.org>" | head -n1 | awk -F '=' '{printf $2}')

if [ "$CHECKTMP" == "$SQUEEZEARCHIVEKEY" ];then
       echo Good
       :
else
       echo bad
       exit 1
fi

#---------------------------------------------------------------------------
#"Squeeze Stable Release Key <debian-release@lists.debian.org>"

SQUEEZESTABLEKEY=" 0E4E DE2C 7F3E 1FC0 D033  800E 6448 1591 B983 21F9"
CHECKTMP=$(apt-key finger | grep -B 1 "Squeeze Stable Release Key <debian-release@lists.debian.org>" | head -n1 | awk -F '=' '{printf $2}')

if [ "$CHECKTMP" == "$SQUEEZESTABLEKEY" ];then
       echo Good
       :
else
       echo bad
       exit 1
fi

#---------------------------------------------------------------------------
#"Debian Archive Automatic Signing Key (7.0/wheezy) <ftpmaster@debian.org>"

WHEEZYARCHIVEKEY=" A1BD 8E9D 78F7 FE5C 3E65  D8AF 8B48 AD62 4692 5553"
CHECKTMP=$(apt-key finger | grep -B 1 "Debian Archive Automatic Signing Key (7.0/wheezy) <ftpmaster@debian.org>" | head -n1 | awk -F '=' '{printf $2}')

if [ "$CHECKTMP" == "$WHEEZYARCHIVEKEY" ];then
       echo Good
       :
else
       echo bad
       exit 1
fi

#---------------------------------------------------------------------------
#"Wheezy Stable Release Key <debian-release@lists.debian.org>"

WHEEZYSTABLEKEY=" ED6D 6527 1AAC F0FF 15D1  2303 6FB2 A1C2 65FF B764"
CHECKTMP=$(apt-key finger | grep -B 1 "Wheezy Stable Release Key <debian-release@lists.debian.org>" | head -n1 | awk -F '=' '{printf $2}')

if [ "$CHECKTMP" == "$WHEEZYSTABLEKEY" ];then
       echo Good
       :
else
       echo bad
       exit 1
fi
