#!/usr/bin/env python

import re
import math
import pickle
import os
import subprocess
import inspect
import copy
import string
import traceback
import random
import signal
import _paceparsesyscalls
import _paceautotest as auto_test
import pdb
import cProfile
import Queue
import threading
import time
import pprint
import code
import sys
import collections
from pacestruct import Struct
from _paceutils import *
import gc
from _paceparsesyscalls import interesting_net_calls
import socket
from platform import machine
from collections import defaultdict

print '-------------------------------------------------------------------------------'
print 'PACE version 0.1' 
print '-------------------------------------------------------------------------------'

fs_interest_calls = ["write", "sync", "delete_dir_entry", "create_dir_entry", "truncate"]
net_interest_calls = ["socket", "bind", "connect", "accept", "listen", "recv", "send"]
calls_of_interest = fs_interest_calls + net_interest_calls

def replay_net_ops(net_op):
	# Think about this:
	# If we are crashing all machines at an instant, you just do not need to worry
	# about replaying the network syscalls. They affect only the in-memory state not per
	# -sistent state. Then why bother? But network calls are vital to find cross deps.
	if net_op.op == 'socket':	
		pass
	elif net_op.op == 'connect':
		pass
	elif net_op.op == 'send':
		pass
	elif net_op.op == 'recv':
		pass
	elif net_op.op == 'listen':
		pass
	elif net_op.op == 'bind':
		pass
	elif net_op.op == 'accept':
		pass
	else:
		assert False

def replay_ops(machine_id, initial_paths_inode_map, rows, replay_dir, stdout_file, use_cached = False):
	def get_stat(path):
		try:
			return os.stat(path)
		except OSError as err:
			return False

	def get_inode_file(inode, mode = None):
		assert isinstance(inode, (int, long))
		if not get_stat(replay_dir + '/.inodes/' + str(inode)):
			if mode == None:
				mode = 0666
			if type(mode) == str:
				mode = safe_string_to_int(mode)
			fd = os.open(replay_dir + '/.inodes/' + str(inode), os.O_CREAT | os.O_WRONLY, mode)
			assert fd > 0
			os.close(fd)
		return replay_dir + '/.inodes/' + str(inode)

	dirinode_map = {} # From initial_inode to replayed_directory_path
	def is_linked_inode_directory(inode):
		assert isinstance(inode, (int, long))
		if inode not in dirinode_map:
			return False
		if dirinode_map[inode] == replay_dir + '/.inodes/' + str(inode):
			return False
		return True

	def get_inode_directory(inode, mode = None):
		assert isinstance(inode, (int, long))
		if inode not in dirinode_map:
			if mode == None:
				mode = 0777
			if type(mode) == str:
				mode = safe_string_to_int(mode)
			os.mkdir(replay_dir + '/.inodes/' + str(inode), mode)
			dirinode_map[inode] = replay_dir + '/.inodes/' + str(inode)
		return dirinode_map[inode]

	def set_inode_directory(inode, dir_path):
		assert isinstance(inode, (int, long))
		dirinode_map[inode] = dir_path

	def initialize_inode_links(initial_paths_inode_map):
		final_paths_inode_map = get_path_inode_map(replay_dir) # This map is used only for assertions
		assert len(final_paths_inode_map) == len(initial_paths_inode_map)

		# Asserting there are no hardlinks on the initial list - if there were, 'cp -R' wouldn't have worked correctly.
		initial_inodes_list = [inode for (inode, entry_type) in initial_paths_inode_map.values()]
		assert len(initial_inodes_list) == len(set(initial_inodes_list))

		os.system("mkdir " + replay_dir + '/.inodes')

		for path in initial_paths_inode_map.keys():
			final_path = path.replace(paceconfig(machine_id).scratchpad_dir, replay_dir, 1)
			assert final_path in final_paths_inode_map
			(initial_inode, entry_type) = initial_paths_inode_map[path]
			(tmp_final_inode, tmp_entry_type) = final_paths_inode_map[final_path]
			assert entry_type == tmp_entry_type
			if entry_type == 'd':
				set_inode_directory(initial_inode, final_path)
			else:
				os.link(final_path, replay_dir + '/.inodes/' + str(initial_inode))

	global cached_rows, cached_dirinode_map
	if use_cached:
		original_replay_dir = replay_dir
		replay_dir = os.path.join(paceconfig(machine_id).scratchpad_dir, 'cached_replay_dir')
		dirinode_map = cached_dirinode_map
		if cached_rows and len(cached_rows) <= len(rows) and rows[0:len(cached_rows)] == cached_rows:
			rows = copy.deepcopy(rows[len(cached_rows):])
			cached_rows += rows
		else:
			cached_rows = copy.deepcopy(rows)
			cached_dirinode_map = {}
			dirinode_map = cached_dirinode_map
			os.system("rm -rf " + replay_dir)
			os.system("cp -R " + paceconfig(machine_id).initial_snapshot + " " + replay_dir)
			initialize_inode_links(initial_paths_inode_map)
	else:
		os.system("rm -rf " + replay_dir)
		os.system("cp -R " + paceconfig(machine_id).initial_snapshot + " " + replay_dir)
		initialize_inode_links(initial_paths_inode_map)

	output_stdout = open(stdout_file, 'w')
	for line in rows:
	#	print line
		if line.op == 'create_dir_entry':
			new_path = get_inode_directory(line.parent) + '/' + os.path.basename(line.entry)
			if line.entry_type == Struct.TYPE_FILE:
				if os.path.exists(new_path):
					os.unlink(new_path)
				assert not os.path.exists(new_path)
				os.link(get_inode_file(line.inode, line.mode), new_path)
			else:
				assert not is_linked_inode_directory(line.inode) # According to the model, there might
					# exist two links to the same directory after FS crash-recovery. However, Linux
					# does not allow this to be simulated. Checking for that condition here - if this
					# assert is ever triggered in a real workload, we'll have to handle this case
					# somehow. Can potentially be handled using symlinks.
				os.rename(get_inode_directory(line.inode, line.mode), new_path)
				set_inode_directory(line.inode, new_path)
		elif line.op == 'delete_dir_entry':
			path = get_inode_directory(line.parent) + '/' + os.path.basename(line.entry)
			if get_stat(path):
				if line.entry_type == Struct.TYPE_FILE:
					os.unlink(path)
				else:
					os.rename(path, replay_dir + '/.inodes/' + str(line.inode)) # Deletion of
						# directory is equivalent to moving it back into the '.inodes' directory.
		elif line.op == 'truncate':
			old_mode = writeable_toggle(get_inode_file(line.inode))
			fd = os.open(get_inode_file(line.inode), os.O_WRONLY)
			assert fd > 0
			os.ftruncate(fd, line.final_size)
			os.close(fd)
			writeable_toggle(get_inode_file(line.inode), old_mode)
		elif line.op == 'write':
			old_mode = writeable_toggle(get_inode_file(line.inode))
			if line.special_write != None:
				if (line.special_write == 'GARBAGE' or line.special_write == 'ZEROS') and line.count > 4096:
					if line.count > 4 * 1024 * 1024:
						BLOCK_SIZE = 1024 * 1024
					else:
						BLOCK_SIZE = 4096
					blocks_byte_offset = int(math.ceil(float(line.offset) / BLOCK_SIZE)) * BLOCK_SIZE
					blocks_byte_count = max(0, (line.offset + line.count) - blocks_byte_offset)
					blocks_count = int(math.floor(float(blocks_byte_count) / BLOCK_SIZE))
					blocks_byte_count = blocks_count * BLOCK_SIZE
					blocks_offset = blocks_byte_offset / BLOCK_SIZE

					pre_blocks_offset = line.offset
					pre_blocks_count = blocks_byte_offset - line.offset
					if pre_blocks_count > line.count:
						assert blocks_byte_count == 0
						pre_blocks_count = line.count
					assert pre_blocks_count >= 0

					post_blocks_count = 0
					if pre_blocks_count < line.count:
						post_blocks_offset = (blocks_byte_offset + blocks_byte_count)
						assert post_blocks_offset % BLOCK_SIZE == 0
						post_blocks_count = line.offset + line.count - post_blocks_offset

					assert pre_blocks_count >= 0
					assert blocks_count >= 0
					assert post_blocks_count >= 0
					assert pre_blocks_count + blocks_count * BLOCK_SIZE + post_blocks_count == line.count
					assert pre_blocks_offset == line.offset
					if pre_blocks_count < line.count:
						assert blocks_offset * BLOCK_SIZE == pre_blocks_offset + pre_blocks_count
					if post_blocks_count > 0:
						assert (blocks_offset + blocks_count) * BLOCK_SIZE == post_blocks_offset

					if line.special_write == 'GARBAGE':
						cmd = "dd if=/dev/urandom of=\"" + get_inode_file(line.inode) + "\" conv=notrunc conv=nocreat status=noxfer "
					else:
						cmd = "dd if=/dev/zero of=\"" + get_inode_file(line.inode) + "\" conv=notrunc conv=nocreat status=noxfer "
					if pre_blocks_count > 0:
						subprocess.check_call(cmd + 'seek=' + str(pre_blocks_offset) + ' count=' + str(pre_blocks_count) + ' bs=1 2>/dev/null', shell=True, )
					if blocks_count > 0:
						subprocess.check_call(cmd + 'seek=' + str(blocks_offset) + ' count=' + str(blocks_count) + ' bs=' + str(BLOCK_SIZE) + '  2>/dev/null', shell=True)
					if post_blocks_count > 0:
						subprocess.check_call(cmd + 'seek=' + str(post_blocks_offset) + ' count=' + str(post_blocks_count) + ' bs=1 2>/dev/null', shell=True)
				elif line.special_write == 'GARBAGE' or line.special_write == 'ZEROS':
					if line.special_write == 'GARBAGE':
						data = string.ascii_uppercase + string.digits
					else:
						data = '\0'
					buf = ''.join(random.choice(data) for x in range(line.count))
					fd = os.open(get_inode_file(line.inode), os.O_WRONLY)
					os.lseek(fd, line.offset, os.SEEK_SET)
					os.write(fd, buf)
					os.close(fd)
					buf = ""
				else:
					assert False
			else:
				if line.dump_file == None:
					buf = line.override_data
				else:
					fd = os.open(line.dump_file, os.O_RDONLY)
					os.lseek(fd, line.dump_offset, os.SEEK_SET)
					buf = os.read(fd, line.count)
					os.close(fd)
				fd = os.open(get_inode_file(line.inode), os.O_WRONLY)
				os.lseek(fd, line.offset, os.SEEK_SET)
				os.write(fd, buf)
				os.close(fd)
				buf = ""
			writeable_toggle(get_inode_file(line.inode), old_mode)
		elif line.op == 'stdout':
			output_stdout.write(line.data)
		elif line.op in interesting_net_calls:
			replay_net_ops(line)
		else:
			assert line.op == 'sync'

	if use_cached:
		os.system('rm -rf ' + original_replay_dir)
		os.system('cp -a ' + replay_dir + ' ' + original_replay_dir)
		replay_dir = original_replay_dir
		cached_dirinode_map = copy.deepcopy(dirinode_map)

	os.system("rm -rf " + replay_dir + '/.inodes')

class DSReplayer:
	def is_legal_gp(self, end_at_points):
		machines_to_consider = [m for m in range(0, len(end_at_points))]
		
		# TODO: Using machine id and index as same things here. Fix this assumption.
		for machine in machines_to_consider:
			deps = self.micro_ops[machine][end_at_points[machine]].implied_deps
			for mach in deps.keys():
				assert mach != machine
				if mach in machines_to_consider:
					if deps[mach] is not None and end_at_points[mach] < deps[mach]:
						return False
		return True

	def is_legal_reordering(self, machine):
		assert self.initialized
		assert self.env_initialized
		
		io_ops_index = 0
		included_io_ops = []
		# TODO: Shameless hack to not look into the atomicity of sync
		micro_op = self.micro_ops[machine][self.__micro_end[machine]]
		if micro_op.op == 'sync' and self.__io_end[machine] < len(micro_op.hidden_io_ops) - 1:
			return False
		for i in range(0, self.__micro_end[machine] + 1):
			micro_op = self.micro_ops[machine][i]
			till = self.__io_end[machine] + 1 if self.__micro_end[machine] == i else len(micro_op.hidden_io_ops)
			for j in range(0, till):
				if not micro_op.hidden_io_ops[j].hidden_omitted:
					included_io_ops.append(io_ops_index)
				elif micro_op.op == 'sync':
					# TODO: Shameless hack to not look into the atomicity of sync
					return False
				elif micro_op.op in interesting_net_calls:
					# We cannot drop a network operation and proceed to the next operations!
					return False
				io_ops_index += 1
		return self.test_suite[machine].test_combo_validity(included_io_ops)

	def __init__(self, pace_configs, sock_config):
		self.initialized = False
		self.machines = []
		self.mops_list_lengths = {}
		self.path_inode_map = {}
		self.micro_ops = {}
		self.__micro_end = {}
		self.__io_end = {}
		self.saved = {}
		self.env_initialized = {}
		self.mops_list_lengths = {}
		self.test_suite = {}
		self.client_index = -1
		self.op_indexes = defaultdict(list)
		self.persistence_op_index = {}
		self.fs_ops = defaultdict(list)
		
		machine_id = 0

		assert len(sock_config['known_ips']) == len(pace_configs)
		assert len(sock_config['known_ports']) > 0
        
		address_map = {}
		i = 0
		for ip in sock_config['known_ips']:
			address_map[i] = ip
			i += 1
		_paceparsesyscalls.set_machine_address_map(address_map)
		_paceparsesyscalls.set_known_ports(sock_config['known_ports'])
		
		# First time parse		
		for pace_config in pace_configs:
			self.machines.append(machine_id)
			init_paceconfig(machine_id, pace_config)
			
			if paceconfig(machine_id).client:
				self.client_index = machine_id
								
			(self.path_inode_map[machine_id], self.micro_ops[machine_id]) = _paceparsesyscalls.get_micro_ops(machine_id)
			cnt = 0
			
			for i in self.micro_ops[machine_id]:
				i.hidden_id = str(cnt)
				cnt = cnt + 1

			self.__micro_end[machine_id] = len(self.micro_ops[machine_id]) - 1
			self.__io_end[machine_id] = 0 # Will be set during the dops_generate() call

			self.saved[machine_id] = dict()
			self.env_initialized[machine_id] = False
			self.mops_list_lengths[machine_id] = len(self.micro_ops[machine_id])
			machine_id += 1

		for machine in self.machines:
			latest_fs_op_index = -1
			self.fs_ops[machine].append(-1)
			for i in range(0, len(self.micro_ops[machine])):
				self.op_indexes[machine].append(i)

				if not (self.micro_ops[machine][i].op in net_interest_calls):
					self.fs_ops[machine].append(i)
					latest_fs_op_index = i

				self.persistence_op_index[(machine, i)] = latest_fs_op_index
				
		assert len(self.machines) == len(pace_configs)
		assert len(self.machines)-1 == self.machines[len(self.machines)-1]
		assert self.client_index != -1 and self.client_index < len(self.machines)
		self.initialized = True

	def print_ops(self, show_io_ops = False, show_tids = False, show_time = False):
		assert self.initialized
		to_print_fs = ''
		to_print = ''
		for machine in self.machines:
			for i in range(0, len(self.micro_ops[machine])):
				micro_id = (str(i))
				tid_info = ''
				if show_tids:
					tid_info = str(self.micro_ops[machine][i].hidden_pid) + '\t' + str(self.micro_ops[machine][i].hidden_tid) + '\t'
				if show_time:
					tid_info += str(self.micro_ops[machine][i].hidden_time) + '\t'
				to_print += '\n' + micro_id + '\t' + tid_info + str(self.micro_ops[machine][i])
				for j in range(0, len(self.micro_ops[machine][i].hidden_io_ops)):
					disk_op_str = str(self.micro_ops[machine][i].hidden_io_ops[j])
					if self.micro_ops[machine][i].hidden_io_ops[j].hidden_omitted:
						disk_op_str = disk_op_str
					if show_io_ops:
						to_print += '\n' + '\t' + str(j) + '\t' + disk_op_str
					if i == self.__micro_end[machine] and j == self.__io_end[machine]:
						to_print += '\n' + '-------------------------------------'
		
		for machine in self.machines:
			for i in range(0, len(self.micro_ops[machine])):
				if self.micro_ops[machine][i].op in interesting_net_calls:
					continue
				
				micro_id = (str(i))
				tid_info = ''
				if show_tids:
					tid_info = str(self.micro_ops[machine][i].hidden_pid) + '\t' + str(self.micro_ops[machine][i].hidden_tid) + '\t'
				if show_time:
					tid_info += str(self.micro_ops[machine][i].hidden_time) + '\t'
				to_print_fs += '\n' + micro_id + '\t' + tid_info + str(self.micro_ops[machine][i])
				for j in range(0, len(self.micro_ops[machine][i].hidden_io_ops)):
					disk_op_str = str(self.micro_ops[machine][i].hidden_io_ops[j])
					if self.micro_ops[machine][i].hidden_io_ops[j].hidden_omitted:
						disk_op_str = disk_op_str
					if show_io_ops:
						to_print_fs += '\n' + '\t' + str(j) + '\t' + disk_op_str			
			to_print_fs += '\n' + '-------------------------------------'
		print to_print
		uppath = lambda _path, n: os.sep.join(_path.split(os.sep)[:-n])

		with open(os.path.join(uppath(paceconfig(0).cached_prefix_states_file, 1), 'micro_ops.fs'), 'w') as f:
			f.write(to_print_fs)
		
		with open(os.path.join(uppath(paceconfig(0).cached_prefix_states_file, 1), 'micro_ops'), 'w') as f:
			f.write(to_print)

		with open(os.path.join(uppath(paceconfig(0).cached_prefix_states_file, 1), 'micro_ops.pickled'), 'w') as f:
			pickle.dump(self.micro_ops, f, protocol = 0)

	def save(self, machine, index):
		assert machine in self.machines
		assert self.env_initialized[machine]
		self.saved[machine][int(index)] = copy.deepcopy(Struct(micro_ops = self.micro_ops[machine],
							micro_end = self.__micro_end[machine],
							io_end = self.__io_end[machine],
							test_suite = self.test_suite[machine]))

	def load(self, machine, index):
		assert machine in self.machines
		assert self.env_initialized[machine]
		assert int(index) in self.saved[machine]
		retrieved = copy.deepcopy(self.saved[machine][int(index)])
		self.micro_ops[machine] = retrieved.micro_ops
		self.__micro_end[machine] = retrieved.micro_end
		self.__io_end[machine] = retrieved.io_end
		self.test_suite[machine] = retrieved.test_suite

	def omitted_ops(self, machine):
		assert machine in self.machines
		assert self.env_initialized[machine]

		omitted_toret = []
		for machine in self.machines:
			for i in range(0, len(self.micro_ops[machine])):
				for hidden_op in self.micro_ops[machine][i].hidden_io_ops:
					if hidden_op.hidden_omitted:
						omitted_toret.append(hidden_op)
		return omitted_toret

	def construct_crashed_dirs(self, dirnames, stdout_files):
		for machine in self.machines:
			assert self.env_initialized[machine]

		assert len(stdout_files) == len(dirnames)
		assert len(stdout_files) == len(self.machines)
		assert len(dirnames) == len(self.machines)

		for machine in self.machines:
			to_replay = []
			
			for i in range(0, self.__micro_end[machine] + 1):
				micro_op = self.micro_ops[machine][i]
				till = self.__io_end[machine] + 1 if self.__micro_end[machine] == i else len(micro_op.hidden_io_ops)
				for j in range(0, till):
					if not micro_op.hidden_io_ops[j].hidden_omitted:
						to_replay.append(micro_op.hidden_io_ops[j])
	                replay_ops(machine, self.path_inode_map[machine], to_replay, dirnames[machine], stdout_files[machine], use_cached = False)
                
	def iops_end_at(self, machine, i, j = None):
		assert machine in self.machines
		assert self.env_initialized[machine]
		if type(i) == tuple:
			assert j == None
			j = i[1]
			i = i[0]
		assert j != None
		self.__micro_end[machine] = i
		self.__io_end[machine] = j

 	def load_cross_dependencies(self):
		assert self.initialized
		for machine in self.machines:
			assert self.env_initialized[machine]
		
		for machine in self.machines:
			index = 0
			mop_list = self.micro_ops[machine]
			for mop in mop_list:
				if hasattr(mop, 'has_cross_deps'):
					if mop.has_cross_deps:
						self.search_and_set_cross_dep_parent(machine, mop)
						if not (hasattr(mop, 'dep_parent') and mop.dep_parent is not None and len(mop.dep_parent) > 0):
							print mop
							sys.exit(0)
						if mop.op == 'recv':
							if not( mop.remaining == 0):
								print mop
								sys.exit(0)
						elif mop.op == 'accept':
							assert len(mop.dep_parent) == 1
						else:
							assert False
						# Since this is cross dep, parent machine should be not us
						assert mop.dep_parent[0] != machine  
				index += 1
			self.save(machine, 0)

	def set_environment(self, fs, net, load_cross_deps = True): 
		for machine in self.machines:

			all_io_ops = []

			for micro_op_id in range(0, len(self.micro_ops[machine])):

				if self.micro_ops[machine][micro_op_id].op in interesting_net_calls:
					net.get_net_ops(self.micro_ops[machine][micro_op_id])
				else:
					fs.get_disk_ops(self.micro_ops[machine][micro_op_id])

				if micro_op_id == self.__micro_end[machine]:
					self.__io_end[machine] = len(self.micro_ops[machine][micro_op_id].hidden_io_ops) - 1

				cnt = 0
				for io_op in self.micro_ops[machine][micro_op_id].hidden_io_ops:
					io_op.hidden_omitted = False
					io_op.hidden_id = cnt
					io_op.hidden_micro_op = self.micro_ops[machine][micro_op_id]
					cnt += 1

				all_io_ops += self.micro_ops[machine][micro_op_id].hidden_io_ops

			for i in range(0, len(all_io_ops)):
				if all_io_ops[i].op == 'stdout':
					all_io_ops[i] = Struct(op = 'write', inode = -1, offset = 0, count = 1, hidden_actual_op = all_io_ops[i]) 

			self.test_suite[machine] = auto_test.ALCTestSuite(all_io_ops)

			for i in range(0, len(all_io_ops)):
				if all_io_ops[i].op == 'write' and all_io_ops[i].inode == -1:
					all_io_ops[i] = all_io_ops[i].hidden_actual_op

			fs.get_deps(all_io_ops)
			fs_dependency_tuples = []
			for i in range(0, len(all_io_ops)):
				if all_io_ops[i].op not in interesting_net_calls:
					for j in sorted(list(all_io_ops[i].hidden_dependencies)):
						fs_dependency_tuples.append((i, j))

			net.get_deps(all_io_ops)
			net_dependency_tuples = []
			for i in range(0, len(all_io_ops)):
				if all_io_ops[i].op in interesting_net_calls:
					for j in sorted(list(all_io_ops[i].hidden_dependencies)):
						net_dependency_tuples.append((i, j))

			self.test_suite[machine].add_deps_to_ops(fs_dependency_tuples + net_dependency_tuples)

			self.env_initialized[machine] = True
			self.saved[machine] = dict()
			self.save(machine, 0)

		#Finally load the cross dependencies
		if load_cross_deps:
			self.load_cross_dependencies()
			self.propagate_dependencies()

	def propagate_dependencies(self):
		for machine in self.machines:
			latest_dep_from_machines = {}
			for m in self.machines:
				if machine != m:
					latest_dep_from_machines[m] = None
			
			for mop in self.micro_ops[machine]:
				if hasattr(mop, 'has_cross_deps'):
					assert hasattr(mop, 'dep_parent') and mop.dep_parent is not None and len(mop.dep_parent) > 0
					max_parent_micro_id = -1
					parent_machines = [dep[0] for dep in mop.dep_parent]
					assert all( x == parent_machines[0] for x in parent_machines)
					parent_machine = parent_machines[0]
					
					for dep in mop.dep_parent:
						parent_micro_id = dep[1]
						if parent_micro_id > max_parent_micro_id:
							max_parent_micro_id = parent_micro_id
						
					latest_dep_from_machines[parent_machine] = parent_micro_id					
				
				mop.implied_deps = copy.deepcopy(latest_dep_from_machines)
				
	def iops_len(self, machine, i = None):
		assert machine in self.machines
		assert self.env_initialized[machine]
		if i == None:
			total = 0
			for micro_op in self.micro_ops[machine]:
				total += len(micro_op.hidden_io_ops)
			return total
		assert i < len(self.micro_ops[machine])
		return len(self.micro_ops[machine][i].hidden_io_ops)

	def conceptual_machines(self):
		return self.machines
	
	def get_prev_op(self, crash_point):
		res_crash_pt = [-1] * len(crash_point)
		for machine in self.machines:
			if self.micro_ops[machine][crash_point[machine]].op == 'fsync' or self.micro_ops[machine][crash_point[machine]].op == 'fdatasync' or\
				self.micro_ops[machine][crash_point[machine]].op == 'file_sync_range':
				j = crash_point[machine] - 1
				while j >= 0:
					if self.micro_ops[machine][j] not in interesting_net_calls:
						assert (self.micro_ops[machine][j] != 'fsync' and self.micro_ops[machine][j] != 'fdatasync' and self.micro_ops[machine][j] != 'file_sync_range')
						res_crash_pt[machine] = j
						break
					else:
						j -= 1
			else:
				res_crash_pt[machine] = crash_point[machine] 

		return tuple(res_crash_pt)

	def persistent_op_index(self, machine, op_index):
		return self.persistence_op_index[(machine, op_index)]

	def fs_ops_indexes(self):
		return self.fs_ops

	def mops_lengths(self):
		toret = {}
		for machine in self.machines:
			toret[machine] = len(self.micro_ops[machine])
		return toret

	def ops_indexes(self):
		return self.op_indexes
	
	def __iops_get_i_j(self, machine, i, j):
		if type(i) == tuple:
			assert j == None
			j = i[1]
			i = i[0]
		assert j != None
		assert i < len(self.micro_ops[machine])
		assert 'hidden_io_ops' in self.micro_ops[machine][i].__dict__
		assert j < len(self.micro_ops[machine][i].hidden_io_ops)
		return (i, j)

	def iops_include(self, machine, i, j = None):
		assert machine in self.machines
		assert self.env_initialized[machine]
		(i, j) = self.__iops_get_i_j(machine, i, j)
		self.micro_ops[machine][i].hidden_io_ops[j].hidden_omitted = False

	def iops_include_group(self, machine_index_map):
		assert len(machine_index_map.keys()) <= len(self.machines) 
		for machine in machine_index_map:
			assert machine in self.machines

		assert self.env_initialized

		for machine in machine_index_map:
			i = machine_index_map[machine][0]
			j = machine_index_map[machine][1]
			(i, j) = self.__iops_get_i_j(machine, i, j)
			self.micro_ops[machine][i].hidden_io_ops[j].hidden_omitted = False

	def iops_omit(self, machine, i, j = None):
		assert machine in self.machines
		assert self.env_initialized
		(i, j) = self.__iops_get_i_j(machine, i, j)
		assert i < len(self.micro_ops[machine])
		assert j < len(self.micro_ops[machine][i].hidden_io_ops)
		
		if self.micro_ops[machine][i].op != 'stdout':
			self.micro_ops[machine][i].hidden_io_ops[j].hidden_omitted = True

	def iops_omit_group(self, machine_index_map):
		assert len(machine_index_map.keys()) <= len(self.machines) 
		for machine in machine_index_map:
			assert machine in self.machines

		assert self.env_initialized

		for machine in machine_index_map:
			i = machine_index_map[machine][0]
			j = machine_index_map[machine][1]
			(i, j) = self.__iops_get_i_j(machine, i, j)
			assert i < len(self.micro_ops[machine])
			assert j < len(self.micro_ops[machine][i].hidden_io_ops)
			
			if self.micro_ops[machine][i].op != 'stdout':
				self.micro_ops[machine][i].hidden_io_ops[j].hidden_omitted = True

	def mops_include(self, machine, i):
		assert machine in self.machines
		assert self.env_initialized
		for j in range(0, self.iops_len(machine, i)):
			self.iops_include(machine, i, j)		

	def mops_include_group(self, machine_index_map):
		assert len(machine_index_map.keys()) <= len(self.machines) 
		for machine in machine_index_map:
			assert machine in self.machines

		assert self.env_initialized

		for machine in machine_index_map:
			i = machine_index_map[machine]
			for j in range(0, self.iops_len(machine, i)):
				self.iops_include(machine, i, j)		
	
	def mops_omit(self, machine, i):
		assert machine in self.machines
		assert self.env_initialized
		if self.micro_ops[machine][i].op != 'stdout':
			for j in range(0, self.iops_len(machine, i)):
				self.iops_omit(machine, i, j)
	
	def mops_omit_group(self, machine_index_map):
		assert len(machine_index_map.keys()) <= len(self.machines)
		for machine in machine_index_map:
			assert machine in self.machines

		assert self.env_initialized

		for machine in machine_index_map:
			i = machine_index_map[machine]
			if self.micro_ops[machine][i].op != 'stdout':
				for j in range(0, self.iops_len(machine, i)):
					self.iops_omit(machine, i, j)
			
	def search_and_set_cross_dep_parent(self, dep_machine_id, dep_micro_op):
		assert dep_micro_op.op == 'accept' or dep_micro_op.op == 'recv'
		assert dep_micro_op.has_cross_deps
		assert dep_machine_id in self.machines
		
		dep_micro_op.dep_parent = []
		to_search_op = 'connect' if dep_micro_op.op == 'accept' else 'send'
		to_search_server_host = dep_micro_op.server_host
		to_search_server_port = dep_micro_op.server_port
		to_search_client_host = dep_micro_op.client_host
		to_search_client_port = dep_micro_op.client_port
		
		check_machines = [machine for machine in self.machines if machine != dep_machine_id]

		if dep_micro_op.op == 'recv':
			assert dep_micro_op.remaining > 0

		for machine in check_machines:
			index = 0
			
			for micro_op in self.micro_ops[machine]:
				cond1 = (micro_op.op == to_search_op)
				cond2 = (hasattr(micro_op, 'server_host') and micro_op.server_host == to_search_server_host)
				cond3 = (hasattr(micro_op, 'server_port') and micro_op.server_port == to_search_server_port)
				cond4 = (hasattr(micro_op, 'client_host') and micro_op.client_host == to_search_client_host)
				cond5 = (hasattr(micro_op, 'client_port') and micro_op.client_port == to_search_client_port)
			
				if cond1 and cond2 and cond3 and cond4 and cond5:
					if to_search_op == 'send':
						assert hasattr(micro_op, 'size')
						assert hasattr(micro_op, 'remaining')

						if micro_op.remaining == 0:
								index += 1
								continue

						if dep_micro_op.remaining <= micro_op.remaining:
							dep_micro_op.dep_parent.append((machine, index)) 
							micro_op.remaining -= dep_micro_op.remaining
							dep_micro_op.remaining = 0
							return
						else:
							# current recv can't be satisfied with current send
							assert dep_micro_op.remaining > micro_op.remaining
							dep_micro_op.remaining -= micro_op.remaining
							micro_op.remaining = 0
							dep_micro_op.dep_parent.append((machine, index))
							index += 1
							continue						
					else:
						# Found a matching micro op
						dep_micro_op.dep_parent.append((machine, index))
						return
				index += 1