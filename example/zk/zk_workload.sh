#!/bin/bash

pkill -f 'java.*zoo*'
ZK_HOME='/mnt/data1/scratch/work/adsl-work/d2s/applications/zookeeper-3.4.8/'
ZK_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PACE_DIR=$(dirname $(dirname $(dirname $(readlink -f "$0"))))

rm -rf traces_dir1
mkdir traces_dir1

rm -rf traces_dir2
mkdir traces_dir2

rm -rf traces_dir3
mkdir traces_dir3

rm -rf traces_dir4
mkdir traces_dir4

cd workload_dir2
LD_PRELOAD=$ZK_DIR/bcv6.2.so $PACE_DIR/pace-record.py --workload_dir . --interesting_stdout_prefix 222 --traces_dir $ZK_DIR/traces_dir2 $ZK_HOME/bin/zkServer.sh start $ZK_DIR/zoo2.cfg &

cd ../workload_dir3
LD_PRELOAD=$ZK_DIR/bcv6.3.so $PACE_DIR/pace-record.py --workload_dir . --interesting_stdout_prefix 333 --traces_dir $ZK_DIR/traces_dir3 $ZK_HOME/bin/zkServer.sh start $ZK_DIR/zoo3.cfg &

cd ../workload_dir4
LD_PRELOAD=$ZK_DIR/bcv6.4.so $PACE_DIR/pace-record.py --workload_dir . --interesting_stdout_prefix 444 --traces_dir $ZK_DIR/traces_dir4 $ZK_HOME/bin/zkServer.sh start $ZK_DIR/zoo4.cfg &

sleep 5

value=$(printf 'b%.s' {1..20480})
echo 'set /zk_test '$value > $ZK_DIR/script
sleep 1

cd ../workload_dir1
LD_PRELOAD=$ZK_DIR/bcv6.1.so $PACE_DIR/pace-record.py --workload_dir . --interesting_stdout_prefix 111 --traces_dir $ZK_DIR/traces_dir1 $ZK_DIR/put.sh

sleep 2

rm -rf $ZK_DIR/script
pkill -f 'java.*zoo*'
ps aux | grep zoo
cd ..

sudo chown -R ram:ram traces_dir*
sudo chown -R ram:ram workload_dir*
sudo chown ram:ram sockconf