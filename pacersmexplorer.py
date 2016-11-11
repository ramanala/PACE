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
import math

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

def get_crash_point_id_string(crash_point):
	toret = ""
	for i in range(0, len(crash_point)):
		c = crash_point[i]
		
		if c == -1:
			c = 'z' # the node has not done any persistent state update
			
		if i < len(crash_point)-1:
			toret += str(c) + "-"
		else:
			toret += str(c)
	return toret

def dict_value_product(dicts):
	return (dict(zip(dicts, x)) for x in itertools.product(*dicts.itervalues()))

def atleast_one_present(machines, currs, ends):
	for m in machines:
		if currs[m] < len(ends[m]):
			return True
	return False

def replay_dir_base_name_RO(crash_point, omit_pt):
	assert type(omit_pt) == dict
	base_name = get_crash_point_id_string(crash_point)
	base_name += "_RO"

	def dict_string(d):
		toret = ''
		for key in d:
			toret += '_' + str(key) + '=' + str(d[key])
		return toret

	base_name += "_OM" + dict_string(omit_pt)
	return base_name

def replay_dir_base_name_ARO(crash_point, omit_pt):
	assert type(omit_pt) == dict
	base_name = get_crash_point_id_string(crash_point) 

	def dict_string(d):
		toret = ''
		for key in d:
			toret += '_' + str(key) + '=' + str(d[key][1])
		return toret

	base_name += "_ARO" + dict_string(omit_pt)
	return base_name

def replay_dir_base_name_AP(crash_point, end_pt):
	assert type(end_pt) == dict
	base_name = get_crash_point_id_string(crash_point) 

	def dict_string(d):
		toret = ''
		for key in d:
			toret += '_' + str(key) + '=' + str(d[key])
		return toret

	base_name += "_AP" + dict_string(end_pt)
	return base_name

def append_or_trunc_ops(replayer, machines, crash_point):
	toret = {}
	for machine in machines:
		curr_op = replayer.micro_ops[machine][crash_point[machine]].op
		toret[machine] =  curr_op == 'append' or curr_op == 'trunc' 
	return toret

def nCr(n,r):
	func = math.factorial
	return func(n) / func(r) / func(n-r)

def get_replay_dirs(machines, base_name):
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

def unique_grp(grps, machines, filter_machines):
	assert len(machines) > 0 and len(filter_machines) < len(machines)
	to_ret = []
	to_ret_set = set()

	temp = {}
	max_for_state = defaultdict(lambda:-1, temp)

	for state in grps:
		state_arr = list(state)
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

def check_logically_same(to_omit_list):
	ops_eq = all(x.op == to_omit_list[0].op for x in to_omit_list)
	if ops_eq:
		name_checking_ops = ['write', 'append', 'creat', 'trunc', 'unlink']
		if to_omit_list[0].op in name_checking_ops:
			name_eq = all(os.path.basename(x.name) == os.path.basename(to_omit_list[0].name) for x in to_omit_list)
			return ops_eq and name_eq
		elif to_omit_list[0].op == 'rename':
			dest_eq = all(os.path.basename(x.dest) == os.path.basename(to_omit_list[0].dest) for x in to_omit_list)
			src_eq = all(os.path.basename(x.source) == os.path.basename(to_omit_list[0].source) for x in to_omit_list)
			return ops_eq and dest_eq and src_eq
		else:
			for omit in to_omit_list:
				if 'fsync' in str(omit):
					return False
			assert False
	else:
		return False

def compute_reachable_global_prefixes(replayer):
	print 'Computing globally reachable prefix states'
	assert paceconfig(0).cached_prefix_states_file is not None and len(paceconfig(0).cached_prefix_states_file) > 0
	prefix_cached_file = paceconfig(0).cached_prefix_states_file

	interesting_prefix_states = []
	final_reachable_prefix_fsync_deps = set()
		
	if not os.path.isfile(prefix_cached_file):
		print 'No cached file. Computing reachable prefixes from scratch.'
		base_lists = replayer.ops_indexes().values()
		
		list0 = base_lists[0]
		list1 = base_lists[1]
		interesting_prefix_states = []

		# Algorithm to find all consistent cuts of persistent states: 
		# Naive method: Let us say there are 3 machines. Consider that the number of events
		# in these traces from three machines as <n1, n2, n3>. So, there are n1 X n2 X n3
		# ways in which these traces could combine.
		# Should we check for everything?
		# No, we can do better; intuition: if i X j is not consistent then any superset of
		# it <i, j , k> for any k is inconsistent.
		
		for index1 in list0:
			for index2 in list1:
				if replayer.is_legal_gp((index1, index2)):
					interesting_prefix_states.append((index1, index2))
								
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
			final_reachable_prefix_fsync_deps.add(candidate)
				
		with open(prefix_cached_file, "w") as f:
			pickle.dump(final_reachable_prefix_fsync_deps, f, protocol = 0)
	else:
		print 'Using cached globally reachable states'
		with open(prefix_cached_file, "r") as f:
			final_reachable_prefix_fsync_deps = pickle.load(f)

	final_reachable_prefix_no_deps = set(list(final_reachable_prefix_fsync_deps)[:])
	assert not bool(final_reachable_prefix_no_deps.symmetric_difference(final_reachable_prefix_fsync_deps))
	
	# We are mostly done here. But there is one more optimization that we could do.
	# if a trace ends with fsync or fdatasync, then it can be skipped for replay 
	# because there is no specific operation that we need to replay fsyncs. However,
	# they are important to calculate FS reordering dependencies. So, we maintain
	# two sets: one with fsync deps (we will use when we apply FS reordering),
	# one with no fsync deps that we will use to replay globally reachable prefixes

	interesting_states_check = set(list(final_reachable_prefix_fsync_deps)[:])
	for state in interesting_states_check:
		machine = 0
		for end_point in state:
			if replayer.micro_ops[machine][end_point].op == 'fsync' or replayer.micro_ops[machine][end_point].op == 'fdatasync' or\
				replayer.micro_ops[machine][end_point].op == 'file_sync_range':
				prev_point = replayer.get_prev_op(state)
				# if subsumed by another GRP, just remove this. If not subsumed, leave it
				if prev_point in interesting_states_check:
					final_reachable_prefix_no_deps.remove(state)
				break
			machine += 1

	assert final_reachable_prefix_fsync_deps is not None and len(final_reachable_prefix_fsync_deps) > 0
	assert final_reachable_prefix_no_deps is not None and len(final_reachable_prefix_no_deps) > 0
	assert final_reachable_prefix_no_deps <= final_reachable_prefix_fsync_deps

	return (final_reachable_prefix_fsync_deps, final_reachable_prefix_no_deps)

def replay_correlated_global_prefix(replayer, interesting_prefix_states, replay = True):
	print 'Checking prefix crash states...' 
	machines = replayer.conceptual_machines()

	replay_start = time.time()
	count = 0
	for crash_point in interesting_prefix_states:
		assert len(crash_point) == len(machines)
		
		base_name = get_crash_point_id_string(crash_point)
		base_name += "_GRP"
		
		for machine in machines:
			replayer.iops_end_at(machine, (crash_point[machine], replayer.iops_len(machine, crash_point[machine]) - 1))

		if replay:
			(base_path, dirnames,stdout_files) = get_replay_dirs(machines, base_name)
			replayer.construct_crashed_dirs(dirnames, stdout_files)
			MultiThreadedChecker.check_later(base_path, dirnames, stdout_files[machines[-1]], get_crash_point_id_string(crash_point))
		count += 1

	if replay: 
		MultiThreadedChecker.wait_and_get_outputs()
		
	replay_end = time.time()
	
	print 'Prefix states : ' + str(count)
	print 'Prefix replay took approx ' + str(replay_end-replay_start) + ' seconds...'

def replay_correlated_atomicity_prefix(replayer, interesting_prefix_states, client_index, replay = True):
	machines = replayer.conceptual_machines()
	fs_ops = replayer.fs_ops_indexes()	
	server_machines = machines[:]
	server_machines.remove(client_index)
	server_count = len(server_machines)
	majority_count = int(len(server_machines) / 2) + 1
	assert server_count == 3 and majority_count == 2
	
	count = 0
	how_many_majorities = 1
	pick_server_count = majority_count

	replay_start = time.time()
			
	replayer.set_environment(defaultfs('count', 3), defaultnet(), load_cross_deps = False)

	apm_imposed_subset_machineset = list(itertools.combinations(server_machines, pick_server_count))	
	assert len(apm_imposed_subset_machineset) == nCr(server_count, majority_count)
	apm_imposed_subset_machineset = apm_imposed_subset_machineset[0:how_many_majorities]
	assert len(apm_imposed_subset_machineset) == 1

	apm_imposed_machines = apm_imposed_subset_machineset[0]

	for machine in machines:
		replayer.load(machine, 0)

	for crash_point in interesting_prefix_states:
		atomic_ends = {}
		atomic_currs = {}
		machine = 0
		for end_point in crash_point:
			if machine in apm_imposed_machines:
				atomic_ends[machine] = range(0, replayer.iops_len(machine, end_point)) 
				atomic_currs[machine] = 0 
			machine += 1

		atomic_end_list = []
		while atleast_one_present(apm_imposed_machines, atomic_currs, atomic_ends):
			atomic_end = {}
			for machine in apm_imposed_machines:
				if atomic_currs[machine] < len(atomic_ends[machine]):
					atomic_end[machine] = atomic_ends[machine][atomic_currs[machine]]
				else:
					atomic_end[machine] = atomic_ends[machine][len(atomic_ends[machine])-1]

				atomic_currs[machine] += 1
			atomic_end_list.append(atomic_end)
	
		for atomic_end in atomic_end_list:
			for machine in server_machines:
				if machine in apm_imposed_machines:
					replayer.iops_end_at(machine, (crash_point[machine], atomic_end[machine]))
				else:
					replayer.iops_end_at(machine, (crash_point[machine], replayer.iops_len(machine, crash_point[machine]) - 1))
				
			replayer.iops_end_at(client_index, (crash_point[client_index], replayer.iops_len(client_index, crash_point[client_index]) - 1))
			base_name = replay_dir_base_name_AP(crash_point, atomic_end)
			count += 1
		
			if replay:
				(base_path, dirnames,stdout_files) = get_replay_dirs(machines, base_name)
				replayer.construct_crashed_dirs(dirnames, stdout_files)
				MultiThreadedChecker.check_later(base_path, dirnames, stdout_files[machines[-1]], base_name)

	if replay:		
		MultiThreadedChecker.wait_and_get_outputs()
		
	replay_end = time.time()

	print 'Atomicity Prefix correlated states : ' + str(count)
	print 'Atomicity Prefix correlated replay took approx ' + str(replay_end-replay_start) + ' seconds...'

def replay_correlated_reordering(replayer, interesting_prefix_states, client_index, replay = True):
	def end_highest_so_far(machine, curr_endpoint):
		machine_dict = can_omit_for_machine_endpoint[machine]
		maximum = -1
		for key in machine_dict.keys():
			if key > maximum and key <= curr_endpoint:
				maximum = key
		return maximum

	machines = replayer.conceptual_machines()
	fs_ops = replayer.fs_ops_indexes()	
	can_omit_ops = {}
	can_omit_for_machine_endpoint = {}
	server_machines = machines[:]
	server_machines.remove(client_index)
	server_count = len(server_machines)
	majority_count = int(len(server_machines) / 2) + 1
	# For now assert for 3 and 2 :)
	assert server_count == 3 and majority_count == 2
	
	for machine in machines:
		can_omit_ops[machine] = defaultdict(list)

	for machine in machines:
		can_omit_for_machine_endpoint[machine] = defaultdict(list)
						
	replay_start = time.time()
	for machine in machines:
		replayer.load(machine, 0)

	# Phase 1: See what all ops can be dropped for each end point in a machine 
	# For example, let's say the GRP is (x, y, z). For x in machine0, there can
	# be multiple ops that are before x and can still be dropped when we end at x
	# For example, consider the follwing:
	# x-2: creat(file)
	# x-1: write(foo)
	# x  : write(bar)
	# In the above trace, it is legal to drop creat when the machine crashes at x.
	# In this phase, we will find all such points that can be dropped for each x.

	for crash_point in interesting_prefix_states:
		for machine in machines:
			replayer.iops_end_at(machine, (crash_point[machine], replayer.iops_len(machine, crash_point[machine]) - 1))
		
		machine_id = 0
		for end_point in crash_point:
			can_end_highest = end_highest_so_far(machine_id, end_point)

			if can_end_highest == -1:
				omit_ops = [fs_op for fs_op in fs_ops[machine_id] if fs_op > -1 and fs_op < end_point]
			else:
				omit_ops1 = can_omit_for_machine_endpoint[machine_id][can_end_highest]
				omit_ops2 = [fs_op for fs_op in fs_ops[machine_id] if fs_op >= can_end_highest and fs_op > -1 and fs_op < end_point]
				omit_ops = omit_ops1 + omit_ops2
			
			can_omit_temp = []
			omit_ops_temp = []
			for i in omit_ops:
				replayer.mops_omit(machine_id, i)
				if replayer.is_legal_reordering(machine_id):
					can_omit_temp.append(i)
					omit_ops_temp.append(i)
				replayer.mops_include(machine_id, i)

			can_omit_for_machine_endpoint[machine_id][end_point] = omit_ops_temp
			can_omit_ops[machine_id][end_point] = can_omit_temp			
			machine_id += 1

	# Phase 2: Using the points collected in phase 1, we can now see what points can be dropped across machines
	# For example, for (x, y, z), if the drop dictionary looks like {x:[0, 2, 4], y:[1], z : [5, 7]}
	# then we have 3*1*2 ways of dropping. Notice that we dont need to check if this is valid reordering
	# It *has* to be valid state as the local drop points have been checked for this condition.

	reordering_count = 0
	pick_server_count = -1
	how_many_majorities = 1
	pick_server_count = majority_count

	apm_imposed_subset_machineset = list(itertools.combinations(server_machines, pick_server_count))
	assert len(apm_imposed_subset_machineset) == nCr(server_count, majority_count)
	apm_imposed_subset_machineset = apm_imposed_subset_machineset[0:how_many_majorities]
	
	for apm_imposed_machines in apm_imposed_subset_machineset:
		for crash_point in interesting_prefix_states:
			omittables = {}

			for machine in machines:
				replayer.iops_end_at(machine, (crash_point[machine], replayer.iops_len(machine, crash_point[machine]) - 1))
		
			for machine in apm_imposed_machines:
				if machine != client_index:
					omittables[machine] = can_omit_ops[machine][crash_point[machine]]

			for omit_pt in list(dict_value_product(omittables)):
				to_omit_list = []
				for mac in omit_pt.keys():
					curr_omit = omit_pt[mac]
					to_omit_list.append(replayer.micro_ops[mac][curr_omit])
			
				if check_logically_same(to_omit_list):
					reordering_count += 1
					replayer.mops_omit_group(omit_pt)
					base_name = replay_dir_base_name_RO(crash_point, omit_pt)
				
					if replay:
						(base_path, dirnames,stdout_files) = get_replay_dirs(machines, base_name)
						replayer.construct_crashed_dirs(dirnames, stdout_files)
						MultiThreadedChecker.check_later(base_path, dirnames, stdout_files[machines[-1]], base_name)

					replayer.mops_include_group(omit_pt)

			del omittables
			omittables = None

	if replay:
		MultiThreadedChecker.wait_and_get_outputs()
		
	replay_end = time.time()
	print 'Reordering correlated states : ' + str(reordering_count)
	print 'Reordering correlated replay took approx ' + str(replay_end-replay_start) + ' seconds...'

def replay_correlated_atomicity_reordering(replayer, interesting_prefix_states, client_index, replay = True):
	machines = replayer.conceptual_machines()
	fs_ops = replayer.fs_ops_indexes()	
	can_omit_ops = {}
	server_machines = machines[:]
	server_machines.remove(client_index)
	server_count = len(server_machines)
	majority_count = int(len(server_machines) / 2) + 1
	assert server_count == 3 and majority_count == 2

	atomicity_reordering_count = 0
	pick_server_count = majority_count
	how_many_majorities = 1

	replay_start = time.time()
			
	replayer.set_environment(defaultfs('count', 3), defaultnet(), load_cross_deps = False)
	apm_imposed_subset_machineset = list(itertools.combinations(server_machines, pick_server_count))
	assert len(apm_imposed_subset_machineset) == nCr(server_count, majority_count)
	apm_imposed_subset_machineset = apm_imposed_subset_machineset[0:how_many_majorities]
	
	for machine in machines:
		replayer.load(machine, 0)

	for apm_imposed_machines in apm_imposed_subset_machineset:
		for crash_point in interesting_prefix_states:

			append_trunc_indexes = append_or_trunc_ops(replayer, server_machines, crash_point)
			if any(append_trunc_indexes.values()):

				# First, end all machine at the GRP point
				machine = 0
				for machine in machines:
					replayer.iops_end_at(machine, (crash_point[machine], replayer.iops_len(machine, crash_point[machine]) - 1))
					machine + 1

				# Next we have to omit the sub (io or disk) ops as we call it
				atomic_omits = {}
				atomic_ro_currs = {}
				machine = 0
				for end_point in crash_point:
					atomic_ro_currs[machine] = 0
					if machine in apm_imposed_machines:
						if append_trunc_indexes[machine]:
							# If it is an append or trunc, break it into pieces and see for its absence
							atomic_omits[machine] = range(0, replayer.iops_len(machine, end_point)) 
						else:
							# if not append, just put a marker. We will exclude this marker later
							atomic_omits[machine] = [str(replayer.iops_len(machine, end_point)-1)]

					machine +=1

				atomic_omit_list = []
				while atleast_one_present(apm_imposed_machines, atomic_ro_currs, atomic_omits):
					atomic_omit = {}
					for machine in apm_imposed_machines:
						if atomic_ro_currs[machine] < len(atomic_omits[machine]):
							atomic_omit[machine] = atomic_omits[machine][atomic_ro_currs[machine]]
						else:
							atomic_omit[machine] = None

						atomic_ro_currs[machine] += 1
					atomic_omit_list.append(atomic_omit)
			
				for atomic_omit_x in atomic_omit_list:
					atomic_omit = atomic_omit_x.copy()
					base_name_prep = atomic_omit_x.copy()
					
					for mac in apm_imposed_machines:
						iop_index = atomic_omit[mac]
						if type(iop_index) == str or iop_index == None:
							del atomic_omit[mac]
						else:
							atomic_omit[mac] = (crash_point[mac], iop_index)
						base_name_prep[mac] = (crash_point[mac], iop_index)

					replayer.iops_omit_group(atomic_omit)
					base_name = replay_dir_base_name_ARO(crash_point, base_name_prep)
					atomicity_reordering_count += 1
					
					if replay:
						(base_path, dirnames,stdout_files) = get_replay_dirs(machines, base_name)
						replayer.construct_crashed_dirs(dirnames, stdout_files)
						MultiThreadedChecker.check_later(base_path, dirnames, stdout_files[machines[-1]], base_name)

					replayer.iops_include_group(atomic_omit)
		
	if replay:		
		MultiThreadedChecker.wait_and_get_outputs()
		
	replay_end = time.time()
	print 'Atomicity reordering correlated states : ' + str(atomicity_reordering_count)
	print 'Atomicity reordering correlated replay took approx ' + str(replay_end-replay_start) + ' seconds...'

def check_corr_crash_vuls(pace_configs, sock_config, threads = 1, replay = False):
	print 'Parsing traces to determine logical operations ...'

	#initialize the replayer
	replayer = DSReplayer(pace_configs, sock_config)

	#set the environment - what file system (defaultfs)? what network(defaultnet)? 
	replayer.set_environment(defaultfs('count', 1), defaultnet(), load_cross_deps = True)

	#did we parse and understand? if yes, print.
	replayer.print_ops(show_io_ops = True)
	print 'Successfully parsed logical operations!'

	if replay == False:
		return
	
	assert threads > 0
	for i in range(0, threads):
		t = MultiThreadedChecker(MultiThreadedChecker.queue, i)
		t.setDaemon(True)
		t.start()
	
	(reachable_prefix_fsync_deps, reachable_prefix_no_deps) = compute_reachable_global_prefixes(replayer)

	grps_0_1_no_deps = unique_grp(reachable_prefix_no_deps, replayer.conceptual_machines(), [0,1])
	grps_0_1_fsync_deps  = unique_grp(reachable_prefix_fsync_deps, replayer.conceptual_machines(), [0,1])
	
	MultiThreadedChecker.reset()
	replay_correlated_global_prefix(replayer, grps_0_1_no_deps, True)

	MultiThreadedChecker.reset()
	replay_correlated_reordering(replayer, grps_0_1_fsync_deps, replayer.client_index, True)

	MultiThreadedChecker.reset()
	replay_correlated_atomicity_reordering(replayer, grps_0_1_no_deps, replayer.client_index, True)

	MultiThreadedChecker.reset()
	replay_correlated_atomicity_prefix(replayer, grps_0_1_no_deps, replayer.client_index,  True)

	uppath = lambda _path, n: os.sep.join(_path.split(os.sep)[:-n])
	os.system('cp ' + os.path.join(uppath(paceconfig(0).cached_prefix_states_file, 1), 'micro_ops') + ' ' + paceconfig(0).scratchpad_dir)