#!/bin/bash
samples/sample_a &
PID=$!
ODIR="/tmp/patch"
[ -d $ODIR ] || mkdir -p /tmp/patch
python generator/main.py samples/sample_a samples/sample_c /tmp/patch || exit 1
patch=$(ls /tmp/patch)
./nsb patch -v 4 -p $PID -f $ODIR/$patch || exit 2
kill -SIGINT $PID
echo $?
