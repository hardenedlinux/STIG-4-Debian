#!/bin/bash
#for more detial to determine which sd is usb
#http://unix.stackexchange.com/questions/60299/how-to-determine-which-sd-is-usb

grep -Hv ^0$ /sys/block/*/removable | \
sed s/removable:.*$/device\\/uevent/ | \
xargs grep -H ^DRIVER=sd | \
sed s/device.uevent.*$/size/ | \
xargs grep -Hv ^0$ | \
cut -d / -f 4 | \
while read line ;do
        if [ "$(mount | grep "$line" | wc -l)" != "$(mount | grep "$line.*noexec" | wc -l )" ];then
                exit 1
        fi
done
