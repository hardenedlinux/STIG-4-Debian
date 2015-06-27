#!/bin/bash
#The hole idea of how to get the origin files' permission is learned from http://sysadminnotebook.blogspot.com/2012/06/how-to-reset-folder-permissions-to.html

TDIR=`mktemp -d`
cd $TDIR
aptitude download auditd
FILES=`dpkg -c auditd*.deb | sed -e '/^d/d' | \
       sed '/audit.rules$/p;s/\/etc\/audit\/rules.d\/audit.rules$/\/etc\/audit\/audit.rules/'`
DIRECTORY=`dpkg -c auditd*.deb | sed -n '/^d/p' | \
          sed -e '/\/usr\/share\/man/d'`
case $1 in
        permission)
                echo "$FILES" | while read FILE;
                do
                        echo "$FILE" | awk '{print $6}' | sed -e 's/^.//g' | while read line;
                        do
                                ORIGIN=$(echo "$FILE" | awk '{print $1}')
                                CURRENT=$(ls -l "$line" | awk '{print $1}')
                                if [ "$CURRENT" != "$ORIGIN" ];then
                                        echo "ORIGIN:$FILE"
                                        echo "CURRENT:$(ls -l $line)"
                                        exit 1
                                fi
                        done
                done
                echo "$DIRECTORY" | while read DIR;
                do
                        echo "$DIR" | awk '{print $6}' | sed -e 's/^.//g' | while read line;
                        do
                                ORIGIN=$(echo "$DIR" | awk '{print $1}' )
                                CURRENT=$(ls -dl "$line" | awk '{print $1}' )
                                if [ "$CURRENT" != "$ORIGIN" ];then
                                        echo "$ORIGIN:$DIR"
                                        echo "$CURRENT:$(ls -dl $line)"
                                        exit 1
                                fi
                        done
                done
        ;;
        owner)
                echo "$FILES" | while read FILE;
                do
                        echo "$FILE" | awk '{print $6}' | sed -e 's/^.//g' | while read line;
                        do
                                ORIGIN=$(echo "$FILE" | awk '{print $2}' | awk -F '/' '{print $1}')
                                CURRENT=$(ls -l "$line" | awk '{print $3}')
                                if [ "$CURRENT" != "$ORIGIN" ];then
                                        echo "ORIGIN:$FILE"
                                        echo "CURRENT:$(ls -l $line)"
                                        exit 1
                                fi
                        done
                done
                echo "$DIRECTORY" | while read DIR;
                do
                        echo "$DIR" | awk '{print $6}' | sed -e 's/^.//g' | while read line;
                        do
                                ORIGIN=$(echo "$DIR" | awk '{print $2}' | awk -F '/' '{print $1}' )
                                CURRENT=$(ls -dl "$line" | awk '{print $3}' )
                                if [ "$CURRENT" != "$ORIGIN" ];then
                                        echo "$ORIGIN:$DIR"
                                        echo "$CURRENT:$(ls -dl $line)"
                                        exit 1
                                fi
                        done
                done
        ;;
        group-owner)
                echo "$FILES" | while read FILE;
                do
                        echo "$FILE" | awk '{print $6}' | sed -e 's/^.//g' | while read line;
                        do
                                ORIGIN=$(echo "$FILE" | awk '{print $2}' | awk -F '/' '{print $2}')
                                CURRENT=$(ls -l "$line" | awk '{print $4}')
                                if [ "$CURRENT" != "$ORIGIN" ];then
                                        echo "ORIGIN:$FILE"
                                        echo "CURRENT:$(ls -l $line)"
                                        exit 1
                                fi
                        done
                done
                echo "$DIRECTORY" | while read DIR;
                do
                        echo "$DIR" | awk '{print $6}' | sed -e 's/^.//g' | while read line;
                        do
                                ORIGIN=$(echo "$DIR" | awk '{print $2}' | awk -F '/' '{print $2}' )
                                CURRENT=$(ls -dl "$line" | awk '{print $4}' )
                                if [ "$CURRENT" != "$ORIGIN" ];then
                                        echo "$ORIGIN:$DIR"
                                        echo "$CURRENT:$(ls -dl $line)"
                                        exit 1
                                fi
                        done
                done
        ;;
        file-hashes)
                dpkg-deb -R audit*.deb .
                echo "$FILES" | grep "bin/" | while read FILE;
                do
                        echo "$FILE" | awk '{print $6}' | sed -e 's/^.//g' | while read line;
                        do
                                ORIGIN=$(sha512sum "$(echo "$line" | sed -e 's/^.\///g')" | awk '{print $1}')
                                CURRENT=$(sha512sum "$line" | awk '{print $1}')
                                if [ "$CURRENT" != "$ORIGIN" ];then
                                        echo "ORIGIN:$FILE"
                                        echo "CURRENT:$(ls -l $line)"
                                        exit 1
                                fi
                        done
                done
        ;;
esac
