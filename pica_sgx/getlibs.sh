#!/bin/bash
#
#
if [ $# -ne 1 ]; then
    echo "Usage: $0 <binary>"
    exit 1
fi

ldd "$1" | while IFS= read -r line; do
    # Assume "libxxx.so => /path/to/libxxx.so (...)"
    path=$(echo "$line" | awk '/=>/ { print $3 }')
    # if null, assume "/lib64/ld-linux-x86-64.so.2 (...)"
    if [ -z "$path" ]; then
        path=$(echo "$line" | awk '$1 ~ /^\// { print $1 }')
    fi
    if [ -n "$path" ] && [ "$path" != "not" ]; then
        echo "$path"
    fi
done
