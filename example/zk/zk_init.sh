#!/bin/bash

pkill -f 'java.*zoo*'
ZK_HOME='/mnt/data1/scratch/work/adsl-work/d2s/applications/zookeeper-3.4.8/'
CURR_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

rm -rf traces_dir1
rm -rf traces_dir2
rm -rf traces_dir3
rm -rf traces_dir4

rm -rf micro_ops*

rm -rf workload_dir1
mkdir workload_dir1

rm -rf workload_dir2
mkdir workload_dir2

rm -rf workload_dir3
mkdir workload_dir3

rm -rf workload_dir4
mkdir workload_dir4

touch workload_dir2/myid
touch workload_dir3/myid
touch workload_dir4/myid

# arbitrary numbers that denote server_id
echo '1' > workload_dir2/myid
echo '2' > workload_dir3/myid
echo '3' > workload_dir4/myid

$ZK_HOME/bin/zkServer.sh start $CURR_DIR/zoo2.cfg
$ZK_HOME/bin/zkServer.sh start $CURR_DIR/zoo3.cfg
$ZK_HOME/bin/zkServer.sh start $CURR_DIR/zoo4.cfg

value=$(printf 'a%.s' {1..8192})
echo 'create /zk_test '$value > script

$ZK_HOME"/bin/zkCli.sh" -server 127.0.0.2:2182 < script

rm -rf script
pkill -f 'java.*zoo*'
ps aux | grep zoo