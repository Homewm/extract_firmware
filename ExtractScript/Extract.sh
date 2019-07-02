#!/bin/bash

FIRM_PATH="$1"
EXTRACT_PATH="$2"
DECOMPRESS_DEEPTH=20

cur_dir=`pwd`
FIRM_NAME="${FIRM_PATH##*/}"
FIRM_DIR="${FIRM_PATH%/*}"

if [ ! -f $FIRM_PATH ];then
    echo "must assign a firmware path"
    exit
fi

[ -d $FIRM_DIR ] && cd $FIRM_DIR

binwalk -e -M -r -q --depth=$DECOMPRESS_DEEPTH "$FIRM_NAME" -C $EXTRACT_PATH/

if [ ! -d $EXTRACT_PATH/_"${FIRM_NAME}".extracted ];then
    touch $EXTRACT_PATH/_"${FIRM_NAME}"_failed
    exit
fi

#给其他用户访问文件夹的权限
chmod o+r ${EXTRACT_PATH}/*
