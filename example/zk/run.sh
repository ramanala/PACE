#!/bin/bash

# To check states, pass in True. It is a good idea to pass in False first and see
# whether the dependency association passes. 

if [ "$#" -ne 1 ]; then
    echo "Specify replay parameter"
fi

ZK_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PACE_DIR=$(dirname $(dirname $(dirname $(readlink -f "$0"))))

$PACE_DIR/pace-check.py --trace_dirs $ZK_DIR/traces_dir2 $ZK_DIR/traces_dir3 $ZK_DIR/traces_dir4 $ZK_DIR/traces_dir1  --threads 1 --sockconf $ZK_DIR/sockconf --checker=$ZK_DIR/zk_checker.py --scratchpad_base /run/shm --rsm --replay $1 