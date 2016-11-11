#!/bin/bash

killall -s 9 redis-server
killall -s 9 redis-server
killall -s 9 redis-server

ps aux | grep redis

PACE_DIR=$(dirname $(dirname $(dirname $(readlink -f "$0"))))
REDIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

rm -rf traces_dir1
mkdir traces_dir1

rm -rf traces_dir2
mkdir traces_dir2

rm -rf traces_dir3
mkdir traces_dir3

rm -rf traces_dir4
mkdir traces_dir4

cd workload_dir2
$PACE_DIR/pace-record.py --workload_dir . --interesting_stdout_prefix 222 --traces_dir $REDIS_DIR/traces_dir2 redis-server $REDIS_DIR/2.conf &

cd ../workload_dir3
LD_PRELOAD=$REDIS_DIR/b.3.so $PACE_DIR/pace-record.py --workload_dir . --interesting_stdout_prefix 333 --traces_dir $REDIS_DIR/traces_dir3 redis-server $REDIS_DIR/3.conf &

cd ../workload_dir4
LD_PRELOAD=$REDIS_DIR/b.4.so $PACE_DIR/pace-record.py --workload_dir . --interesting_stdout_prefix 444 --traces_dir $REDIS_DIR/traces_dir4 redis-server $REDIS_DIR/4.conf &

sleep 5
echo 'Sleeping before firing client so that the cluster is up for sure'
sleep 5

cd ../workload_dir1
value=$(printf 'b%.s' {1..8192})
LD_PRELOAD=$REDIS_DIR/bc.1.so $PACE_DIR/pace-record.py --workload_dir . --interesting_stdout_prefix 111 --traces_dir $REDIS_DIR/traces_dir1 $REDIS_DIR/put.py workload $value &

sleep 5
echo 'Waiting to drain, just to be safe'
sleep 5

killall -s 9 redis-server
killall -s 9 redis-server
killall -s 9 redis-server
ps aux | grep redis

chown -R ram:ram $REDIS_DIR/workload_dir*
chown -R ram:ram $REDIS_DIR/traces_dir*