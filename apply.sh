#!/bin/bash
samples/sample_a &
PID=$!
ODIR="/tmp/patch"
[ -d $ODIR ] || mkdir -p /tmp/patch
python generator/main.py samples/sample_a samples/sample_b /tmp/patch
patch=$(ls /tmp/patch)
./nsb patch -v 4 -p $PID -f $ODIR/$patch
kill -SIGINT $PID
echo $?
