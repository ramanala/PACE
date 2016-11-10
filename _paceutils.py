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
import argparse
import subprocess
import re

__paceconfigs = {}
common_props = ['checker_tool', 'scratchpad_dir', 'debug_level', 'ignore_ioctl', 'ignore_mmap', 'ignore_stacktrace', 'ignore_file_read', 'cached_prefix_states_file']

def init_paceconfig(machine_id, args):
	global __paceconfigs
	__paceconfig = None
	assert machine_id >= 0
	parser = argparse.ArgumentParser()
	parser.add_argument('--strace_file_prefix', dest = 'strace_file_prefix', type = str, default = False)
	parser.add_argument('--initial_snapshot', dest = 'initial_snapshot', type = str, default = False)
	parser.add_argument('--checker_tool', dest = 'checker_tool', type = str, default = False)
	parser.add_argument('--base_path', dest = 'base_path', type = str, default = False)
	parser.add_argument('--starting_cwd', dest = 'starting_cwd', type = str, default = False)
	parser.add_argument('--interesting_stdout_prefix', dest = 'interesting_stdout_prefix', type = str, default = False)
	parser.add_argument('--collapse_recv', dest = 'collapse_recv', type = bool, default = False)
	parser.add_argument('--interesting_path_string', dest = 'interesting_path_string', type = str, default = False)
	parser.add_argument('--scratchpad_dir', dest = 'scratchpad_dir', type = str, default = '/tmp')
	parser.add_argument('--debug_level', dest = 'debug_level', type = int, default = 0)
	parser.add_argument('--ignore_ioctl', dest = 'ignore_ioctl', type = list, default = [])
	parser.add_argument('--ignore_mmap', dest = 'ignore_mmap', type = bool, default = False)
	parser.add_argument('--ignore_stacktrace', dest = 'ignore_stacktrace', type = bool, default = False)
	parser.add_argument('--ignore_file_read', dest = 'ignore_file_read', type = bool, default = True)
	parser.add_argument('--cached_prefix_states_file', dest = 'cached_prefix_states_file', type = str, default = False)
	parser.add_argument('--client', dest = 'client', type = bool, default = False)
	
	__paceconfig = parser.parse_args('')
	for key in __paceconfig.__dict__:
		if key in args:
			__paceconfig.__dict__[key] = args[key]
	
	assert __paceconfig.strace_file_prefix != False
	assert __paceconfig.initial_snapshot != False
	assert __paceconfig.base_path != False and __paceconfig.base_path.startswith('/')
	if __paceconfig.base_path.endswith('/'):
		__paceconfig.base_path = __paceconfig.base_path[0 : -1]

	if __paceconfig.interesting_path_string == False:
		__paceconfig.interesting_path_string = r'^' + __paceconfig.base_path

	if 'starting_cwd' not in __paceconfig.__dict__ or __paceconfig.starting_cwd == False:
		__paceconfig.starting_cwd = __paceconfig.base_path

	def all_same(items):
		return all(x == items[0] for x in items)

	assert __paceconfig.scratchpad_dir != False
	__paceconfig.machine_id = machine_id
	__paceconfigs[machine_id] = __paceconfig
	
	for prop in common_props:
		to_check = []		
		for machine in __paceconfigs.keys():
			to_check.append(getattr(__paceconfigs[machine], prop))
		
		assert all_same(to_check) == True
						
def paceconfig(machine_id):
	# machine_id can be None for common properties and we can return any paceconfig 
	# but for simplicity, just make sure that everyone passes machine context to obtain
	# config
	return __paceconfigs[machine_id]

def get_path_inode_map(directory):
	result = {}
	while(directory.endswith('/')):
		directory = directory[ : -1]
	for inode_path in subprocess.check_output("find " + directory + " -printf '%i %p %y\n'", shell = True).split('\n'):
		if inode_path == '':
			continue
		(inode, path, entry_type) = inode_path.split(' ')
		inode = int(inode)
		assert entry_type == 'd' or entry_type == 'f'
		result[path] = (inode, entry_type)
	return result

def colorize(s, i):
	return '\033[00;' + str(30 + i) + 'm' + s + '\033[0m'

def coded_colorize(s, s2 = None):
	colors=[1,3,5,6,11,12,14,15]
	if s2 == None:
		s2 = s
	return colorize(s, colors[hash(s2) % len(colors)])

def colors_test(fname):
	f = open(fname, 'w')
	for i in range(0, 30):
		f.write(colorize(str(i), i) + '\n')
	f.close()

def short_path(machine_id, name):
	if not __paceconfigs[machine_id] or not name.startswith(__paceconfigs[machine_id].base_path):
		return name
	return name.replace(re.sub(r'//', r'/', __paceconfigs[machine_id].base_path + '/'), '', 1)

# The input parameter must already have gone through original_path()
def initial_path(machine_id, name):
	if not name.startswith(__paceconfigs[machine_id].base_path):
		return False
	toret = name.replace(__paceconfigs[machine_id].base_path, __paceconfigs[machine_id].initial_snapshot + '/', 1)
	return re.sub(r'//', r'/', toret)

# The input parameter must already have gone through original_path()
def replayed_path(machine_id, name):
	if not name.startswith(__paceconfigs[machine_id].base_path):
		return False
	toret = name.replace(__paceconfigs[machine_id].base_path, __paceconfigs[machine_id].scratchpad_dir + '/', 1)
	return re.sub(r'//', r'/', toret)

def safe_string_to_int(s):
	try:
		if len(s) >= 2 and s[0:2] == "0x":
			return int(s, 16)
		elif s[0] == '0':
			return int(s, 8)
		return int(s)
	except ValueError as err:
		print s
		raise err

def is_interesting(machine_id, path):
	return re.search(paceconfig(machine_id).interesting_path_string, path)

def writeable_toggle(path, mode = None):
	if mode == 'UNTOGGLED':
		return
	elif mode != None:
		os.chmod(path, mode)
	if os.access(path, os.W_OK):
		return 'UNTOGGLED'
	if not os.access(path, os.W_OK):
		old_mode = os.stat(path).st_mode
		os.chmod(path, 0777)
		return old_mode
