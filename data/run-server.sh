#!/bin/bash
SERVER_CORE=12
SERVER_LOG=../data/MEASURE-SERVER.txt
SERVER_CMD=../tls_sgx/host_server

echo "Server Core: " $SERVER_CORE > $SERVER_LOG
sudo cpupower -c $SERVER_CORE frequency-set -g performance
for i in {1..10}; do
    echo "**************************" >> $SERVER_LOG
    echo "$i" >> $SERVER_LOG
    echo "**************************" >> $SERVER_LOG
    sudo taskset -c $SERVER_CORE $SERVER_CMD  -V -r 2 >> $SERVER_LOG 2>&1
done
sudo cpupower -c $SERVER_CORE frequency-set -g powersave
