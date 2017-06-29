#!/bin/bash

case $1 in
        cron)
                if ! service --status-all | grep "+.*cron";then
                        exit 1
                fi
        ;;
        ntp)
                if ! service --status-all | grep "+.*ntp";then
                        exit 1
                fi
        ;;
        postfix)
                if ! service --status-all | grep "+.*postfix";then
                        exit 1
                fi
        ;;
        autofs)
                if service --status-all | grep "+.*autofs";then
                        exit 1
                fi
        ;;
esac
