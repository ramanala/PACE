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

import os
import subprocess
import cProfile
import Queue
import threading
import time
import pprint
import code
import sys
import collections
import gc
from _paceutils import *
from pace import DSReplayer
from pacedefaultfs import defaultfs, defaultnet
import itertools
import pickle
from collections import defaultdict

class MultiThreadedChecker(threading.Thread):
	queue = Queue.Queue()
	outputs = {}
	
	def __init__(self, queue, thread_id='0'):
		threading.Thread.__init__(self)
		self.queue = MultiThreadedChecker.queue
		self.thread_id = str(thread_id)

	def __threaded_check(self, base_path, dirnames, client_stdout, crashid):
		assert type(paceconfig(0).checker_tool) in [list, str, tuple]
		
		dirname_param = ''
		for dirname in dirnames.values():
			dirname_param += str(dirname) + str('@')
		
		args = [paceconfig(0).checker_tool, dirname_param, base_path, client_stdout, self.thread_id]
		retcode = subprocess.call(args)
		MultiThreadedChecker.outputs[crashid] = retcode
		
	def run(self):
		while True:
			task = self.queue.get()
			self.__threaded_check(*task)
			self.queue.task_done()

	@staticmethod
	def check_later(base_path, dirnames, client_stdout,  retcodeid):
		MultiThreadedChecker.queue.put((base_path, dirnames, client_stdout, retcodeid))

	@staticmethod
	def reset():
		assert MultiThreadedChecker.queue.empty()
		MultiThreadedChecker.outputs = {}

	@staticmethod
	def wait_and_get_outputs():
		MultiThreadedChecker.queue.join()
		return MultiThreadedChecker.outputs

def __get_workload_range(pace_configs, pace_conf_file, interesting_prefix_states):
	pace_conf = []
	with open(pace_conf_file, "r") as f:
		pace_conf = pickle.load(f)
	assert len(pace_conf.keys()) == len(pace_configs)
	
	workload_range = []
	for state in interesting_prefix_states:
		belongs = True
		for key in pace_conf.keys():
			if not (state[key] >= pace_conf[key][0] and state[key] <= pace_conf[key][1]):
				belongs = False
				break

		if belongs:
			workload_range.append(state)

	print 'Getting workload range : ' + str(len(workload_range)) 
	return workload_range

def unique_gvp(gvps, machines, filter_machines):
	assert len(machines) > 0 and len(filter_machines) < len(machines)
	to_ret = []
	to_ret_set = set()

	temp = {}
	max_for_state = defaultdict(lambda:-1, temp)

	for state in gvps:
		state_arr = list(state)
		#print state_arr
		for machine in machines:
			if machine not in filter_machines:
				val = state_arr[machine]
				del state_arr[machine]
				if tuple(state_arr) not in max_for_state.keys():
					max_for_state[tuple(state_arr)] = val
				else:
					if max_for_state[tuple(state_arr)] < val:
						max_for_state[tuple(state_arr)] = val
				state_arr.insert(machine, max_for_state[tuple(state_arr)])
		to_ret_set.add(tuple(state_arr))	
	return to_ret_set

def __get_crash_point_id_string(crash_point):
	toret = ""
	for i in range(0, len(crash_point)):
		c = crash_point[i]
		
		if c == -1:
			c = 'z'
			
		if i < len(crash_point)-1:
			toret += str(c) + "-"
		else:
			toret += str(c)
	return toret

def __get_replay_dirs(machines, base_name):
	dirnames = {}
	base_path = os.path.join(paceconfig(0).scratchpad_dir, base_name)
	for machine in machines:
		os.system('rm -rf ' + base_path)
		os.system('mkdir -p ' + base_path)
		dirnames[machine] = os.path.join(base_path , 'rdir-' + str(machine))
	
	stdout_files = {}
	for machine_id in dirnames.keys():
			stdout_files[machine_id] = os.path.join(base_path, str(machine_id) + '.input_stdout')
	return (base_path, dirnames,stdout_files) 


def __get_interesting_prefixes(replayer):
	print 'Getting interesting states'
	assert paceconfig(0).cached_prefix_states_file is not None and len(paceconfig(0).cached_prefix_states_file) > 0
	prefix_cached_file = paceconfig(0).cached_prefix_states_file

	interesting_prefix_states = []
	final_interesting_states_reorder = set()
	ins_start = time.time()
		
	if not os.path.isfile(prefix_cached_file):
		print 'No cached file. Will compute GVP.'
		product_producers = replayer.ops_indexes()
		base_lists = product_producers.values()
		list0 = base_lists[0]
		list1 = base_lists[1]
		interesting_prefix_states = []
		cross_prod = reduce(lambda x,y: x*y, map(len, base_lists))
		print 'Cross product : ' + str(cross_prod)
		
		for index1 in list0:
			for index2 in list1:
				if replayer.is_legal_gp((index1, index2)):
					interesting_prefix_states.append((index1, index2))
								
		print 'Pair completed : ' +str(len(interesting_prefix_states))
		
		for i in range(2, len(base_lists)):
			interesting_prefix_cache = []
			for index in base_lists[i]:
				for inter in interesting_prefix_states:
					to_check = inter + (index, )
					if replayer.is_legal_gp(to_check):
						interesting_prefix_cache.append(to_check)				
			interesting_prefix_states = interesting_prefix_cache
			
		for state in interesting_prefix_states:
			index = 0
			candidate = []
			for point in state:
				candidate.append(replayer.persistent_op_index(index, point))
				index += 1
			candidate = tuple(candidate)
			final_interesting_states_reorder.add(candidate)
				
		with open(prefix_cached_file, "w") as f:
			pickle.dump(final_interesting_states_reorder, f, protocol = 0)
	else:
		print 'Using cached prefix states file'
		with open(prefix_cached_file, "r") as f:
			final_interesting_states_reorder = pickle.load(f)


	final_interesting_states_other = set(list(final_interesting_states_reorder)[:])
	interesting_states_check = set(list(final_interesting_states_reorder)[:])
	for state in interesting_states_check:
		machine = 0
		for end_point in state:
			if replayer.micro_ops[machine][end_point].op == 'fsync' or replayer.micro_ops[machine][end_point].op == 'fdatasync' or\
				replayer.micro_ops[machine][end_point].op == 'file_sync_range':
				prev_point = replayer.get_prev_op(state)
				# if subsumed by another GVP, just remove this. If not subsumed, leave it
				if prev_point in interesting_states_check:
					final_interesting_states_other.remove(state)
				break
			machine += 1

	ins_end = time.time()
	assert final_interesting_states_reorder is not None and len(final_interesting_states_reorder) > 0
	assert final_interesting_states_other is not None and len(final_interesting_states_other) > 0
	return (final_interesting_states_reorder, final_interesting_states_other)

def globally_valid_prefix(replayer, interesting_prefix_states, replay = True):
	print 'Producing prefix crash states...' 
	machines = replayer.conceptual_machines()

	replay_start = time.time()
	count = 0
	for crash_point in interesting_prefix_states:
		assert len(crash_point) == len(machines)
		
		base_name = __get_crash_point_id_string(crash_point)
		base_name += "_GVP"
		
		for machine in machines:
			replayer.iops_end_at(machine, (crash_point[machine], replayer.iops_len(machine, crash_point[machine]) - 1))

		if replay:
			(base_path, dirnames,stdout_files) = __get_replay_dirs(machines, base_name)
			replayer.construct_crashed_dirs(dirnames, stdout_files)
			MultiThreadedChecker.check_later(base_path, dirnames, stdout_files[machines[-1]], __get_crash_point_id_string(crash_point))
		count += 1
			
	if replay: 
		MultiThreadedChecker.wait_and_get_outputs()
		
	replay_end = time.time()
	
	print 'Prefix states : ' + str(count)
	print 'Prefix replay took approx ' + str(replay_end-replay_start) + ' seconds...'

def reordering(replayer, interesting_prefix_states, replay = True):
	print 'Producing reordering crash states...' 

	machines = replayer.conceptual_machines()
	fs_ops = replayer.fs_ops_indexes()	
	can_omit_for_machine_endpoint = {}
	for machine in machines:
		can_omit_for_machine_endpoint[machine] = defaultdict(list)
	
	def end_highest_so_far(machine, curr_endpoint):
		machine_dict = can_omit_for_machine_endpoint[machine]
		maximum = -1
		for key in machine_dict.keys():
			if key > maximum and key <= curr_endpoint:
				maximum = key
		return maximum
					
	replay_start = time.time()
	count = 0

	for machine in machines:
		replayer.load(machine, 0)
	
	for crash_point in interesting_prefix_states:	
		for machine in machines:
			replayer.iops_end_at(machine, (crash_point[machine], replayer.iops_len(machine, crash_point[machine]) - 1))
		
		machine_id = 0
		for end_point in crash_point:
			if machine_id != 0:
				machine_id += 1
				continue

			can_end_highest = end_highest_so_far(machine_id, end_point)
			
			if can_end_highest == -1:
				can_omit_ops = [fs_op for fs_op in fs_ops[machine_id] if fs_op > -1 and fs_op < end_point]
			else:
				can_omit_ops1 = can_omit_for_machine_endpoint[machine_id][can_end_highest]
				can_omit_ops2 = [fs_op for fs_op in fs_ops[machine_id] if fs_op >= can_end_highest and fs_op > -1 and fs_op < end_point]
				can_omit_ops = can_omit_ops1 + can_omit_ops2
			
			can_omit_temp = []
			for i in can_omit_ops:
				replayer.mops_omit(machine_id, i)
				if replayer.is_legal_reordering(machine_id):
					can_omit_temp.append(i)
					base_name = __get_crash_point_id_string(crash_point)
					base_name += "_RO"
					base_name += "_END=" + str(machine_id) + "-" + str(end_point)
					base_name += "_OM=" + str(machine_id) + "-" + str(i)

					if replay:
						(base_path, dirnames,stdout_files) = __get_replay_dirs(machines, base_name)
						replayer.construct_crashed_dirs(dirnames, stdout_files)
						MultiThreadedChecker.check_later(base_path, dirnames, stdout_files[machines[-1]], base_name)
					
					count += 1
					if (count % 1000) == 0:
						print count
						print base_name
				replayer.mops_include(machine_id, i)

			can_omit_for_machine_endpoint[machine_id][end_point] = can_omit_temp			
			machine_id += 1
			
	if replay:
		MultiThreadedChecker.wait_and_get_outputs()
		
	replay_end = time.time()
	print 'Reordering states : ' + str(count)
	print 'Reordering replay took approx ' + str(replay_end-replay_start) + ' seconds...'

def atomicity(replayer, interesting_prefix_states, replay = True):
	print 'Producing atomicity crash states...' 
	
	machines = replayer.conceptual_machines()
	replay_start = time.time()
	count = 0
	replayer.set_environment(defaultfs('count', 3), defaultnet(), load_cross_deps = False)
		
	for machine in machines:
		replayer.load(machine, 0)

	for crash_point in interesting_prefix_states:
		machine = 0
		for end_point in crash_point:
			if machine != 0:
				#print machine
				machine += 1
				continue

			for other in machines:
				if other != machine:
					replayer.iops_end_at(other, (crash_point[other], replayer.iops_len(other, crash_point[other]) - 1))
			
			for j in range(0, replayer.iops_len(machine, end_point)):
				base_name = __get_crash_point_id_string(crash_point) 
				base_name += "_AP"
				base_name += ("_END=" + str(machine) + "-" + str(end_point) + "-" + str(j))
				replayer.iops_end_at(machine, (end_point, j))
				count += 1
				#print base_name
				if replay:
					(base_path, dirnames, stdout_files) = __get_replay_dirs(machines, base_name)
					replayer.construct_crashed_dirs(dirnames, stdout_files)
					MultiThreadedChecker.check_later(base_path, dirnames, stdout_files[machines[-1]], base_name)
		
			for k in range(0, replayer.iops_len(machine, end_point)-1):
				replayer.iops_omit(machine, (end_point, k))
				if replayer.is_legal_reordering(machine):
					base_name = __get_crash_point_id_string(crash_point)
					base_name += "_ARO"
					base_name += ("_END=" + str(machine) + "-" + str(end_point) + "-" + str(j))
					base_name += ("_OM=" + str(machine) + "-" + str(end_point) + "-" + str(k))
					count += 1
					#print base_name
					if replay:
						(base_path, dirnames,stdout_files) = __get_replay_dirs(machines, base_name)
						replayer.construct_crashed_dirs(dirnames, stdout_files)
						MultiThreadedChecker.check_later(base_path, dirnames, stdout_files[machines[-1]], base_name)
				
				replayer.iops_include(machine, (end_point, k))				
			machine += 1		
	
	if replay:		
		MultiThreadedChecker.wait_and_get_outputs()
		
	replay_end = time.time()
	print 'Atomicity check states : ' + str(count)
	print 'Atomicity replay took approx ' + str(replay_end-replay_start) + ' seconds...'

def check_corr_crash_vuls(pace_configs, sock_config, threads = 1, replay = False):
	print 'Parsing traces to determine logical operations ...'
	replayer = DSReplayer(pace_configs, sock_config)
	replayer.set_environment(defaultfs('count', 1), defaultnet(), load_cross_deps = True)
	replayer.print_ops(show_io_ops = True)


	uppath = lambda _path, n: os.sep.join(_path.split(os.sep)[:-n])
	
	pace_conf_file = os.path.join(uppath(paceconfig(0).cached_prefix_states_file, 1), 'pace_conf')
	assert os.path.exists(pace_conf_file), "Hint: Run the prot tool to produce pace_conf file!"
	
	if replay == False:
		return
	
	assert threads > 0
	for i in range(0, threads):
		t = MultiThreadedChecker(MultiThreadedChecker.queue, i)
		t.setDaemon(True)
		t.start()

		
	(interesting_prefix_states_reorder, interesting_prefix_states_other) = __get_interesting_prefixes(replayer)
	workload_range_reorder = __get_workload_range(pace_configs, pace_conf_file, interesting_prefix_states_reorder)
	workload_range_other = __get_workload_range(pace_configs, pace_conf_file, interesting_prefix_states_other)
	#gvp_1 = unique_gvp(interesting_prefix_states_other, replayer.conceptual_machines(), [1])
	#gvp_1_r = unique_gvp(interesting_prefix_states_reorder, replayer.conceptual_machines(), [1])

	gvp_0 = unique_gvp(interesting_prefix_states_other, replayer.conceptual_machines(), [0])
	gvp_0_r = unique_gvp(interesting_prefix_states_reorder, replayer.conceptual_machines(), [0])
	
	MultiThreadedChecker.reset()
	globally_valid_prefix(replayer, interesting_prefix_states_other, False)

	MultiThreadedChecker.reset()
	reordering(replayer, gvp_0_r, False)
	
	MultiThreadedChecker.reset()
	atomicity(replayer, gvp_0, False)

	os.system('cp ' + os.path.join(uppath(paceconfig(0).cached_prefix_states_file, 1), 'micro_ops') + ' ' + paceconfig(0).scratchpad_dir)