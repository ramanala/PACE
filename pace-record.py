#!/usr/bin/env python

# Copyright (c) 2016 Ramnatthan Alagappan. All Rights Reserved.
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import sys
import os
import subprocess
import pickle

parser = argparse.ArgumentParser()
parser.add_argument('--workload_dir', required = True)
parser.add_argument('--traces_dir', required = True)
parser.add_argument('--interesting_stdout_prefix', required = True)
parser.add_argument('--verbose', action='store_true')
parser.add_argument('remainder', nargs = argparse.REMAINDER)

args = parser.parse_args()
args.workload_dir = os.path.abspath(args.workload_dir)
args.traces_dir = os.path.abspath(args.traces_dir)

uppath = lambda _path, n: os.sep.join(_path.split(os.sep)[:-n])

subprocess.check_output("rm -rf " + os.path.join(uppath(args.traces_dir, 1), "prefix_states_cached"), shell = True)
subprocess.check_output("rm -rf " + os.path.join(uppath(args.traces_dir, 1), "micro_ops*"), shell = True)
subprocess.check_output("rm -rf " + os.path.join(uppath(args.traces_dir, 1), "path_inode_map*"), shell = True)

if args.verbose:
	print 'Taking initial snapshot'
subprocess.check_output("cp -R " + args.workload_dir + " " + os.path.join(args.traces_dir, "initial_snapshot"), shell = True)

if args.verbose:
	print 'Recording config information'
f = open(os.path.join(args.traces_dir, "config"), "w")
output = dict()
output['starting_wd'] = os.getcwd()
output['workload_dir'] = args.workload_dir
output['interesting_stdout_prefix'] = args.interesting_stdout_prefix
pickle.dump(output, f, protocol = 0)
f.close()

if args.verbose:
	print 'Running workload with strace'
workload_strace_command = "alice-strace -s 0 -ff -tt -T -o".split(' ') + [os.path.join(args.traces_dir, "strace.out")] + args.remainder
subprocess.call(workload_strace_command)

if args.verbose:
	print 'Recording symbol information'
subprocess.check_output("alice-strace-retrieve-symbols " + os.path.join(args.traces_dir, "strace.out"), shell = True)