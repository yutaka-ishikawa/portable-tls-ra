#!/bin/bash
DAEMON_CORE=11
DAEMON_LOG=../data/MEASURE-DAEMON.txt
DAEMON_CMD=./tpmdaemon

sudo rm -f /tmp/sock-tpmd-daemon
echo "Daemon Core: " $DAEMON_CORE > $DAEMON_LOG
sudo cpupower -c $DAEMON_CORE frequency-set -g performance
for i in {1..10}; do
    echo "**************************" >> $DAEMON_LOG
    echo "$i" >>  $DAEMON_LOG
    echo "**************************" >> $DAEMON_LOG
    sudo $DAEMON_CMD /tmp/sock-tpmd-daemon 2>> $DAEMON_LOG
done
sudo cpupower -c $DAEMON_CORE frequency-set -g powersave
