#!/bin/bash

# To check states, pass in True. It is a good idea to pass in False first and see
# whether the dependency association passes. 

if [ "$#" -ne 1 ]; then
    echo "Specify replay parameter"
fi

REDIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PACE_DIR=$(dirname $(dirname $(dirname $(readlink -f "$0"))))

$PACE_DIR/pace-check.py --trace_dirs $REDIS_DIR/traces_dir2 $REDIS_DIR/traces_dir3 $REDIS_DIR/traces_dir4 $REDIS_DIR/traces_dir1  --threads 1 --sockconf $REDIS_DIR/sockconf --checker=$REDIS_DIR/redis_checker.py --scratchpad_base /run/shm --explore non-rsm --rule_set "r3,r4" --replay $1 