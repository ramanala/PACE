#!/usr/bin/python
import os
import sys
import redis

mode = sys.argv[1]
value = sys.argv[2]

assert mode == 'init' or mode == 'workload'

r_server = redis.Redis('127.0.0.2', 6002)
r_server.set('key1', value)
r_server.wait(3, 1000)

if mode == 'workload':
	print '111:Done\n'