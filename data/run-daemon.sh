#!/bin/bash
DAEMON_CORE=11
DAEMON_LOG=../data/MEASURE-DAEMON.txt

echo "Daemon Core: " $DAEMON_CORE > $CLIENT_LOG
sudo cpupower -c $DAEMON_CORE frequency-set -g performance
for i in {1..10}; do
    echo "**************************"
    echo "$i"
    echo "**************************"
    sudo ./host_client -D /tmp/sock-tpmd-daemon -s 10.102.51.44 >> $DAEMON_LOG
done
sudo cpupower -c $DAEMON_CORE frequency-set -g powersave
