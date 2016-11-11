#!/bin/bash

killall redis-server
killall redis-cli
CURR_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

rm -rf traces_dir*
rm -rf prefix_states_cached
rm -rf micro_ops*

rm -rf workload_dir1
mkdir workload_dir1

rm -rf workload_dir2
mkdir workload_dir2

rm -rf workload_dir3
mkdir workload_dir3

rm -rf workload_dir4
mkdir workload_dir4

redis-server 2.conf --dir ./workload_dir2 &
redis-server 3.conf --dir ./workload_dir3 &
redis-server 4.conf --dir ./workload_dir4 &

sleep 5
echo 'Sleeping before firing client so that the cluster is up for sure'
sleep 5

value=$(printf 'a%.s' {1..8192})
./put.py init $value

killall -s 9 redis-server
ps aux | grep redis