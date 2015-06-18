#!/bin/bash
MODE=$(ls -l /etc/group | awk '{print $1}')

if [ "$(printf "%c" "$MODE")" == "-" ];then  #First char at MODE(----------)
        :   
else
        exit 1
fi

TEMP=${MODE#?}                 #remove first char at MODE and save at $TEMP

printf "%c" "$TEMP" | grep -w "^r$\|^-$"

if [ $? -eq 0 ];then
        :   
else
        exit 1
fi

TEMP=${TEMP#?}

printf "%c" "$TEMP" | grep -w "^w$\|^-$"

if [ $? -eq 0 ];then
        :   
else
        exit 1
fi

TEMP=${TEMP#?}

printf "%c" "$TEMP" | grep -w "^-$"

if [ $? -eq 0 ];then
        :   
else
        exit 1
fi

TEMP=${TEMP#?}

printf "%c" "$TEMP" | grep -w "^r$\|^-$"

if [ $? -eq 0 ];then
        :   
else
        exit 1
fi

TEMP=${TEMP#?}

printf "%c" "$TEMP" | grep -w "^-$"
if [ $? -eq 0 ];then
        :
else
        exit 1
fi

TEMP=${TEMP#?}

printf "%c" "$TEMP" | grep -w "^-$"

if [ $? -eq 0 ];then
        :
else
        exit 1
fi

TEMP=${TEMP#?}

printf "%c" "$TEMP" | grep -w "^r$\|^-$"

if [ $? -eq 0 ];then
        :
else
        exit 1
fi

TEMP=${TEMP#?}

printf "%c" "$TEMP" | grep -w "^-$"

if [ $? -eq 0 ];then
        :
else
        exit 1
fi

TEMP=${TEMP#?}

printf "%c" "$TEMP" | grep -w "^-$"

if [ $? -eq 0 ];then
        :
else
        exit 1
fi

