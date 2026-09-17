#!/bin/bash
#
if [ $# -ne 1 ]; then
    echo "Usage: $0 <log file>"
    exit 1
fi

cd ../openssh-portable
make distclean
#./configure
#make sshd sshd-auth sshd-session

CORE=10
LOG=$1
echo $CMD
echo "Core: " $CORE > $LOG
sudo cpupower -c all frequency-set -g performance

taskset -c $CORE time ./configure >> $LOG 2>&1
taskset -c $CORE time make sshd sshd-auth sshd-session >> $LOG 2>&1

sudo cpupower -c all frequency-set -g powersave
