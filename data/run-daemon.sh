#!/bin/bash
#
#
DAEMON_CORE=11
DAEMON_LOG=../data/MEASURE-DAEMON_$(date +%Y%m%d_%H%M%S).txt
DAEMON_CMD=./tpmdaemon

sudo rm -f /tmp/sock-tpmd-daemon
echo "Daemon Core: " $DAEMON_CORE > $DAEMON_LOG
sudo cpupower -c $DAEMON_CORE frequency-set -g performance

echo "**************************" >> $DAEMON_LOG
echo "**************************" >> $DAEMON_LOG
sudo taskset -c $DAEMON_CORE $DAEMON_CMD /tmp/sock-tpmd-daemon 2>> $DAEMON_LOG

echo "Done"
sudo cpupower -c $DAEMON_CORE frequency-set -g powersave
