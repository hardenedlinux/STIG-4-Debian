#!/bin/bash

# Find the profile scripts/apt-key-finger-list.data validation key is present in the system.

KEY_FINGER_COUNT=`grep -c APTKEYFINGER scripts/apt-key-finger-list.data`

for ((i=1;i<=${KEY_FINGER_COUNT};i++))
do
  CHECKKEYFINGER=`grep APTKEYFINGER scripts/apt-key-finger-list.data | sed -n "${i}p" | awk -F '=' '{print $2}'`
  CHECKTMP=$(apt-key finger | grep -c "$CHECKKEYFINGER")
  if [ "$CHECKTMP" -eq 1 ]; then
     :
  else
    exit 1
  fi
done


