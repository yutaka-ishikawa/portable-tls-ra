#!/bin/bash
CLIENT_CORE=10
CLIENT_LOG=../data/MEASURE-NORMAL-CLIENT.txt
CLIENT_CMD=./tlsclient

echo "Client Core: " $CLIENT_CORE > $CLIENT_LOG
sudo cpupower -c $CLIENT_CORE frequency-set -g performance
for i in {1..10}; do
    echo "**************************" >> $CLIENT_LOG
    echo "$i" >> $CLIENT_LOG
    echo "**************************" >> $CLIENT_LOG
    sudo taskset -c $CLIENT_CORE $CLIENT_CMD  -D 10.102.51.44 -p 1100 \
	 >> $CLIENT_LOG 2>&1
    sleep 3
done
sudo cpupower -c $CLIENT_CORE frequency-set -g powersave
