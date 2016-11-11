#!/bin/bash

ZK_HOME='/mnt/data1/scratch/work/adsl-work/d2s/applications/zookeeper-3.4.8/'
CURR_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

$ZK_HOME"/bin/zkCli.sh" -server 127.0.0.2:2182 < $CURR_DIR/script
printf "111:Done\n"