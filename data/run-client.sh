#!/bin/bash
CLIENT_CORE=10
CLIENT_LOG=../data/MEASURE-CLIENT.txt

sudo cpupower -c $CLIENT_CORE frequency-set -g performance
for i in {1..10}; do
    echo "**************************"
    echo "$i"
    echo "**************************"
    sudo ./host_client -D /tmp/sock-tpmd-daemon -s 10.102.51.44 >> $CLIENT_LOG
    sleep 1
done
sudo cpupower -c $CLIENT_CORE frequency-set -g powersave
