#!/bin/bash

VERSION='2.0'
DATE=`date +%F`
LOG=STIG-for-Debian-$DATE

TEXTFILE=stig-debian-9.txt
export SUCCESS_FLAG=0
export FAIL_FLAG=0

function version() {
	echo "STIG for Debian Compliance Checking Tools(v.$VERSION)"
}

function usage() {
cat << EOF
usage: $0 [options]

  -s    Start checking and output repot in html format.
  -v    Display version
  -h    Display help

Default report is output in current directory(STIG-for-Debian-*.html)

STIG for Debian Compliance Checking Tools (v$VERSION)

Ported from DISA RHEL 7 STIG
EOF
}

if [ $# -eq 0 ];then
        usage
        exit 1
elif [ $# -gt 1 ];then
        tput setaf 1;echo -e "\033[1mERROR: Too much parameter\033[0m";tput sgr0
        echo
        usage
        exit 1
fi

while getopts ":csvhqC" OPTION; do
        case $OPTION in
                s)      
			ENABLE_HTML=1
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
                        tput setaf 1;echo -e "\033[1mERROR: Wrong parameter!\033[0m";tput sgr0
                        echo
                        usage
                        exit 1
                        ;;
        esac
done

if [[ $EUID -ne 0 ]]; then
		tput setaf 1; #Setting Output Color To Red 
		echo -e "\033[1mPlease re-run this script as root!\033[0m";
		tput sgr0 #Turn off all attributes
	exit 1
fi

RUNTIME=$(date)
printf "Script Run: $RUNTIME\nStart checking process...\n\n"

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

HTML_OVERVIEW_LOG="$LOG"_overview.html

function html_overview_gen_prologue() {
        cat html/html_overview_template_head1.html > $HTML_OVERVIEW_LOG
        echo "STIG for Debian Compliance Checking $DATE" >>$HTML_OVERVIEW_LOG #HTML title
        cat html/html_overview_template_style.html >> $HTML_OVERVIEW_LOG
        cat html/html_overview_template_script.html >> $HTML_OVERVIEW_LOG
        cat html/html_overview_template_head2.html >> $HTML_OVERVIEW_LOG
        cat html/html_overview_template_body1.html >> $HTML_OVERVIEW_LOG
        echo "$DATE" >> $HTML_OVERVIEW_LOG
        cat html/html_overview_template_body2.html >> $HTML_OVERVIEW_LOG
}

function html_overview_gen_middle() {
        cat html/html_overview_template_middle.html >> $HTML_OVERVIEW_LOG
}

function html_overview_gen_epilogue() {
        cat html/html_overview_template_footer.html >> $HTML_OVERVIEW_LOG
}

function html_overview_output() {
        echo '<tr><td data-title="ID">'"$RULE_ID"'</td>' >>$HTML_OVERVIEW_LOG
        echo '<td data-title="ID">'"$RULE_TITLE"'</td>' >>$HTML_OVERVIEW_LOG
        echo '<td data-title="ID">'"$LEVEL"'</td>' >>$HTML_OVERVIEW_LOG
        echo '<td data-title="ID">'"$STATUS"'</td></tr>' >>$HTML_OVERVIEW_LOG
}

function html_overview_manual_output() {
        echo '<tr><td data-title="ID">'"$RULE_ID"'</td>' >>$HTML_OVERVIEW_LOG
        echo '<td data-title="ID">'"$RULE_TITLE"'</td>' >>$HTML_OVERVIEW_LOG
        echo '<td data-title="ID">'"$LEVEL"'</td></tr>' >>$HTML_OVERVIEW_LOG
}

HTML_DETIALS_LOG="$LOG"_detials.html

function html_detials_gen_prologue() {
        cat html/html_detials_template_head1.html > $HTML_DETIALS_LOG
        echo "STIG for Debian Compliance Checking  $DATE" >>$HTML_DETIALS_LOG #HTML title
        cat html/html_detials_template_style.html >> $HTML_DETIALS_LOG
        cat html/html_detials_template_script.html >> $HTML_DETIALS_LOG
        cat html/html_detials_template_head2.html >> $HTML_DETIALS_LOG
        cat html/html_detials_template_body1.html >> $HTML_DETIALS_LOG
        echo "$DATE" >> $HTML_DETIALS_LOG
        cat html/html_detials_template_body2.html >> $HTML_DETIALS_LOG
}

function html_detials_gen_middle() {
        cat html/html_detials_template_middle.html >> $HTML_DETIALS_LOG
}

function html_detials_gen_epilogue() {
        cat html/html_detials_template_footer.html >> $HTML_DETIALS_LOG
}

function html_detials_output() {
        echo '<section><font style="font-weight:bold;">Rule Title: </font>'"$RULE_TITLE"'<br />' >>$HTML_DETIALS_LOG
        echo '<font style="font-weight:bold;">Rule ID: </font>'"$RULE_ID"'<br />'>>$HTML_DETIALS_LOG
        echo '<font style="font-weight:bold;">Status: </font>'"$STATUS"'<br />' >>$HTML_DETIALS_LOG
        echo '<font style="font-weight:bold;">Description: </font>'"$(echo "$QUESTION_DESC" | sed -e 's/\\n\\n/<br \/>/g' -e 's/\\n/<br \/>/g')"'<br />' >>$HTML_DETIALS_LOG
        echo '<font style="font-weight:bold;">Check Content: </font>'"$(echo "$CHECK_CONTENT" | sed -e 's/\\n\\n/<br \/>/g' -e 's/\\n/<br \/>/g')"'<br />' >>$HTML_DETIALS_LOG
        echo '<font style="font-weight:bold;">Fix Method: </font>'"$(echo "$FIX" | sed -e 's/\\n\\n/<br \/>/g' -e 's/\\n/<br \/>/g')"'<br /></section>' >>$HTML_DETIALS_LOG
}

function html_detials_manual_output() {
        echo '<section><font style="font-weight:bold;">Rule Title: </font>'"$RULE_TITLE"'<br />' >>$HTML_DETIALS_LOG
        echo '<font style="font-weight:bold;">Rule ID: </font>'"$RULE_ID"'<br />'>>$HTML_DETIALS_LOG
        echo '<font style="font-weight:bold;">Description: </font>'"$(echo "$QUESTION_DESC" | sed -e 's/\\n\\n/<br \/>/g' -e 's/\\n/<br \/>/g')"'<br />' >>$HTML_DETIALS_LOG
        echo '<font style="font-weight:bold;">Check Content: </font>'"$(echo "$CHECK_CONTENT" | sed -e 's/\\n\\n/<br \/>/g' -e 's/\\n/<br \/>/g')"'<br />' >>$HTML_DETIALS_LOG
        echo '<font style="font-weight:bold;">Fix Method: </font>'"$(echo "$FIX" | sed -e 's/\\n\\n/<br \/>/g' -e 's/\\n/<br \/>/g')"'<br /></section>' >>$HTML_DETIALS_LOG
}

function output() {

        EXIT_STATUS=$2
        LOCATION=$(sed -n "/$1/=" $TEXTFILE)
        #output rule id
        RULE_ID=$(sed -n "$LOCATION"p "$TEXTFILE" | sed "s/Rule ID: //" )
	#output severity level
	LEVEL=$(sed -n "$((LOCATION+=1))"p "$TEXTFILE" | sed "s/Severity: //" )
        #output rule title
        RULE_TITLE=$(sed -n "$((LOCATION+=2))"p "$TEXTFILE" | sed "s/Rule Title: //")
        #output description
        QUESTION_DESC=$(sed -n "$((LOCATION+=3))"p "$TEXTFILE" | sed "s/Description: //")
        #output check content
        CHECK_CONTENT=$(sed -n "$((LOCATION+=4))"p "$TEXTFILE" | sed "s/Check_content: //")
        #output fixtext
        FIX=$(sed -n "$((LOCATION+=5))"p $TEXTFILE | sed "s/Fixtext: //")
        HTML_FIX=$(echo $FIX)

        if [ $EXIT_STATUS -eq 0 ];then
                STATUS="PASS"
                ((SUCCESS_FLAG++))
        else
                STATUS='<font color="#FE4365">FAILED</font>'
                ((FAIL_FLAG++))
        fi

        if [ $ENABLE_HTML = "1" ];then
            html_overview_output >> $HTML_OVERVIEW_LOG
            html_detials_output >> $HTML_DETIALS_LOG
        fi
}

function manual_output() {

        LOCATION=$(sed -n "/$1/=" $TEXTFILE)
        #output rule id
        RULE_ID=$(sed -n "$LOCATION"p "$TEXTFILE" | sed "s/Rule ID: //" )
        #output severity level
        LEVEL=$(sed -n "$((LOCATION+=1))"p "$TEXTFILE" | sed "s/Severity: //" )
        #output rule title
        RULE_TITLE=$(sed -n "$((LOCATION+=2))"p "$TEXTFILE" | sed "s/Rule Title: //")
        #output description
        QUESTION_DESC=$(sed -n "$((LOCATION+=3))"p "$TEXTFILE" | sed "s/Description: //")
        #output check content
        CHECK_CONTENT=$(sed -n "$((LOCATION+=4))"p "$TEXTFILE" | sed "s/Check_content: //")
        #output fixtext
        FIX=$(sed -n "$((LOCATION+=5))"p $TEXTFILE | sed "s/Fixtext: //")
        HTML_FIX=$(echo $FIX)

        if [ $ENABLE_HTML = "1" ];then
            html_overview_manual_output >> $HTML_OVERVIEW_LOG
            html_detials_manual_output >> $HTML_DETIALS_LOG
        fi
}



if [ $ENABLE_HTML = "1" ]; then
        html_overview_gen_prologue
        html_detials_gen_prologue
fi
##########################################################################

######CAT I


bash scripts/check-nullok.sh >/dev/null 2>&1 &
spinner $!
output "SV-86561r1_rule" $?



######CAT II

######CAT III

##########################################################################

if [ $ENABLE_HTML = "1" ];then
        html_overview_gen_middle
        html_detials_gen_middle
fi

#####Manual checking

cat manual.txt | while read line;do
        manual_output "$line"
done


if [ $ENABLE_HTML = "1" ];then
        html_overview_gen_epilogue
        html_detials_gen_epilogue
fi

#####Statistics

sed -i -e "s/Pass count/Pass count: $SUCCESS_FLAG/" -e "s/Failed count/Failed count: $FAIL_FLAG/" STIG-for-Debian-$DATE_*.html
