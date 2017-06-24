#!/bin/bash

# Find the profile scripts/apt-key-finger-list.data validation key is present in the system.

key_finger_count=`grep APTKEYFINGER scripts/apt-key-finger-list.data | wc -l`

for ((i=1;i<=${key_finger_count};i++))
do
  CHECKKEYFINGER=`grep APTKEYFINGER scripts/apt-key-finger-list.data | sed -n "${i}p" | awk -F '=' '{print $2}'`
  CHECKTMP=$(apt-key finger | grep "$CHECKKEYFINGER" | wc -l)
  if [ $CHECKTMP -eq 1 ]; then
     :
  else
    exit 1
  fi
done


