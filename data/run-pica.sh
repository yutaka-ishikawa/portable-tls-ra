#!/bin/bash
PICA_CORE=9
PICA_LOG=../data/MEASURE-PICA_$(date +%Y%m%d_%H%M%S).txt
PICA_CMD_REG="./host -r pica.conf  -D /tmp/sock-tpmd-daemon"
PICA_CMD_EXE="./host -D /tmp/sock-tpmd-daemon"
PICA_CMD_EXE_WITHOUT="./host -e -D /tmp/sock-tpmd-daemon"

$PICA_CMD_REG

echo "Pica Core: " $PICA_CORE > $PICA_LOG
sudo cpupower -c $PICA_CORE frequency-set -g performance
#
#
echo "!!!!!!!!!!!!!!! PICA !!!!!!!!!!!!!!"
echo "!!!!!!!!!!!!!!! PICA !!!!!!!!!!!!!!" >> $PICA_LOG
for i in {1..10}; do
    echo "**************************" >> $PICA_LOG
    echo "$i" >>  $PICA_LOG
    echo "**************************" >> $PICA_LOG
    taskset -c $PICA_CORE $PICA_CMD_EXE >> $PICA_LOG 2>&1
done
echo "!!!!!!!!!!!!!!! Without PICA !!!!!!!!!!!!!!"
echo "!!!!!!!!!!!!!!! Without PICA !!!!!!!!!!!!!!">> $PICA_LOG
for i in {1..10}; do
    echo "**************************" >> $PICA_LOG
    echo "$i" >>  $PICA_LOG
    echo "**************************" >> $PICA_LOG
    taskset -c $PICA_CORE $PICA_CMD_EXE_WITHOUT >> $PICA_LOG 2>&1
done

sudo cpupower -c $PICA_CORE frequency-set -g powersave
