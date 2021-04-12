#!/bin/bash

tmp_path="hello.txt.tmp"
path="hello.txt"
index=0
dst_dir="/tmp/test/"
dur=1
if [ -n "$1" ]; then
    count=$1
else
    count=20
fi


writing() {
    if [ ! -d $dst_dir ]; then
        mkdir -p $dst_dir
    fi
    cd $dst_dir
    if [ -f $tmp_path ]; then
        rm $tmp_path
    fi
    if [ -f $path ]; then 
        rm $path
    fi

    while [ $index -lt $count ]; do
        echo "$index some content" >> $tmp_path
        sleep $dur
        index=`expr $index + 1`
    done;

    mv $tmp_path $path
}


writing

if [ "$2" == "rm" ]; then
    sleep 10
    rm $path
fi
