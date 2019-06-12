#!/bin/bash
case $1 in
        core-dumps)
                if [ "$(ulimit -c)" -ne 0 ];then
                        exit 1
                fi
        ;;
        maxlogins)
                LIMIT_FOUND=0
                while read -r line ; do
                    LIMIT_FOUND=$((LIMIT_FOUND+1))
                    if [ "$line" -lt 10 ];then
                      exit 1
                    fi
                done < <(grep -P "^\s*\*\s+hard\s+maxlogins\s+\d+\s*$" /etc/security/limits.conf /etc/security/limits.d/*.conf | cut -d' ' -f4)
                if [ "$LIMIT_FOUND" -le 0 ];then
                  exit 1
                fi
        ;;
esac
