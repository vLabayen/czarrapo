#!/bin/bash

byte_size=$(echo $1 | awk '/[0-9]$/{print $1;next};/[mM]$/{printf "%u\n", $1*(1024*1024);next};/[kK]$/{printf "%u\n", $1*1024;next}')
cat /dev/urandom | base64 | head -c $byte_size > $2