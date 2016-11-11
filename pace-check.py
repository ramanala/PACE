#!/usr/bin/env python

#Copyright (c) 2016 Ramnatthan Alagappan

#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.

import argparse
import sys
import os
import subprocess
import pickle
import pacedefaultexplorer
import pacersmexplorer
import bruteforceexplorer

parser = argparse.ArgumentParser()
parser.add_argument('--checker', required = True, help = 'Location of the checker')
parser.add_argument('--trace_dirs', nargs='+', required = True, help = 'Locations of the trace directories')
parser.add_argument('--sockconf', required = True, help = 'Config file specifying known IPs and ports')
parser.add_argument('--replay', required = True, help = 'If true, will replay else just print', default = 'False')
parser.add_argument('--threads', type = int, default = 1)
parser.add_argument('--debug_level', type = int, default = 0, choices = range(0, 3))
parser.add_argument('--ignore_mmap', type = bool, default = True)
parser.add_argument('--ignore_stacktrace', type = bool, default = True)
parser.add_argument('--ignore_file_read', type = bool, default = True)
parser.add_argument('--scratchpad_base', type = str)
parser.add_argument('--explore', dest='explore', action='store', choices=['rsm','non-rsm','bruteforce'], help='Type of exploration strategy', required = True)

args = parser.parse_args()
args.checker = os.path.abspath(args.checker)
for i in range(0, len(args.trace_dirs)):
	args.trace_dirs[i] = os.path.abspath(args.trace_dirs[i])

args.sockconf = os.path.abspath(args.sockconf)
args.replay = True if args.replay == 'True' or args.replay == '1' else False

lines = []
with open(args.sockconf, 'r') as f:
	for line in f:
		lines.append(line)

assert len(lines) == 3
assert 'known_ips:' in lines[0]
lines[0]=lines[0].replace('known_ips:', '').replace('\n','')
ips = lines[0].split(',')

assert 'known_ports:' in lines[1]
lines[1]=lines[1].replace('known_ports:', '').replace('\n','')
ports = []

for port in lines[1].split(','):
	ports.append(int(port))
	
assert len(ips) == len(args.trace_dirs)

assert 'client_index' in lines[2]
lines[2] = lines[2].replace('client_index:', '').replace('\n','')
client_index = int(lines[2])
assert client_index < len(ips)

sock_config = {}
sock_config['known_ips'] = ips
sock_config['known_ports'] = ports

def try_mkdir(name):
	try:
		os.system("rm -rf " + name)
		os.mkdir(name)
		return True
	except OSError as e:
		return False
  
if args.scratchpad_base == None:
	args.scratchpad_base = '/run/shm'
	
os.system('rm -rf '  + args.scratchpad_base + '/pace*')
folder = os.path.join(args.scratchpad_base, 'pace-' + str(os.getpid()))
if try_mkdir(folder):
	scratchpad_dir = folder

assert scratchpad_dir is not None

pace_configs = []
uppath = lambda _path, n: os.sep.join(_path.split(os.sep)[:-n])

index = 0
for trace_dir in args.trace_dirs:
	f = open(os.path.join(trace_dir, "config"), "r")
	config = pickle.load(f)
	f.close()
	assert config is not None

	pace_config = dict()
	pace_config['strace_file_prefix'] = os.path.join(trace_dir, "strace.out")
	pace_config['initial_snapshot'] = os.path.join(trace_dir, "initial_snapshot")
	pace_config['base_path'] = config['workload_dir']
	pace_config['starting_cwd'] = config['starting_wd']
	pace_config['interesting_stdout_prefix'] = config['interesting_stdout_prefix']
	pace_config['checker_tool'] = args.checker
	pace_config['debug_level'] = args.debug_level
	pace_config['ignore_mmap'] = args.ignore_mmap
	pace_config['ignore_stacktrace'] = True
	pace_config['ignore_file_read'] = True
	pace_config['scratchpad_dir'] = scratchpad_dir
	pace_config['cached_prefix_states_file'] = os.path.join(uppath(trace_dir, 1), 'prefix_states_cached') 
	pace_config['client'] = False
	if index == client_index:
		pace_config['client'] = True
		
	pace_configs.append(pace_config)
	index += 1

if args.explore == 'rsm':
	pacersmexplorer.check_corr_crash_vuls(pace_configs, sock_config, threads = args.threads, replay = args.replay)
elif args.explore == 'non-rsm':
	pacenonrsmexplorer.check_corr_crash_vuls(pace_configs, sock_config, threads = args.threads, replay = args.replay)
else:
	assert args.explore == 'bruteforce'
	bruteforceexplorer.check_corr_crash_vuls(pace_configs, sock_config, threads = args.threads, replay = args.replay)