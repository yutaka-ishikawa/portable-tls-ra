#!/bin/bash
SERVER_CORE=12
SERVER_LOG=../data/SERVER-CLIENT.txt

sudo cpupower -c $CLIENT_CORE frequency-set -g performance
for i in {1..10}; do
    echo "**************************"
    echo "$i"
    echo "**************************"
    sudo ./host_client -D /tmp/sock-tpmd-daemon -s 10.102.51.44 >> $SERVER_LOG
    sleep 1
done
sudo cpupower -c $SERVER_CORE frequency-set -g powersave
