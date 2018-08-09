#!/bin/bash

# example $1 is stig-rhel-7-v1r4.txt
OUTPUTFILE=$1

if [ $1 == "" ]; then
	OUTPUTFILE="stig-rhel-7.txt"
fi

python xml2text.py | sed -e "s/Description:.*<VulnDiscussion>/Description: /g" -e "s/<\/VulnDiscussion>.*$//g" -e "s/^Fixtext: \['/Fixtext: /g" -e "s/']$//g" -e 's/"]$//g' -e "s/Check_content: \['/Check_content: /g" -e 's/Check_content: \["/Check_content: /g' -e "s/Satisfies:.*$//g" > ${OUTPUTFILE}
