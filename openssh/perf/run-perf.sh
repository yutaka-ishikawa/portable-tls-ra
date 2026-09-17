#!/bin/bash
#
if [ $# -ne 2 ]; then
    echo "Usage: $0 <perf binary> <result file>"
    exit 1
fi
CORE=10
CMD=$1
LOG=$2
echo $CMD
echo "Core: " $CORE > $LOG
sudo cpupower -c $CORE frequency-set -g performance
#
taskset -c $CORE $CMD >> $LOG 2>&1
#
sudo cpupower -c $CORE frequency-set -g powersave
