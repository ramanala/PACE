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

import pickle
import csv
import sys
import commands
import uuid
import copy
import os
import traceback
import pprint
from _paceutils import *
from pacestruct import Struct
from collections import namedtuple
from collections import defaultdict
from xml.dom.domreg import well_known_implementations
import math

innocent_syscalls = ["mknod", "_exit","_newselect","_sysctl","access","acct","add_key","adjtimex",
"afs_syscall","alarm","alloc_hugepages","arch_prctl","break","brk","cacheflush",
"capget","capset","clock_getres","clock_gettime","clock_nanosleep","clock_settime",
"create_module","delete_module","epoll_create","epoll_create1","epoll_ctl","epoll_pwait",
"epoll_wait","eventfd","eventfd2","exit","exit_group","faccessat","fadvise64",
"fadvise64_64","fgetxattr","flistxattr","flock","free_hugepages","fstat","fstat64",
"fstatat64","fstatfs","fstatfs64","ftime","futex","get_kernel_syms","get_mempolicy","get_robust_list",
"get_thread_area","getcpu","getcwd","getdents","getdents64","getegid","getegid32","geteuid",
"geteuid32","getgid","getgid32","getgroups","getgroups32","getitimer","getpeername","getpagesize",
"getpgid","getpgrp","getpid","getpmsg","getppid","getpriority","getresgid","getresgid32",
"getresuid","getresuid32","getrlimit","getrusage","getsid","getsockname","getsockopt","gettid",
"gettimeofday","getuid","getuid32","getxattr","gtty","idle","init_module","inotify_add_watch",
"inotify_init","inotify_init1","inotify_rm_watch","ioperm","iopl","ioprio_get","ioprio_set",
"ipc","kexec_load","keyctl","kill","lgetxattr","listxattr","llistxattr",
"lock","lookup_dcookie","lstat","lstat64","madvise","madvise1","mbind","migrate_pages",
"mincore","mlock","mlockall","move_pages","mprotect","mpx",
"mq_getsetattr","mq_notify","mq_open","mq_timedreceive","mq_timedsend","mq_unlink","msgctl","msgget",
"msgrcv","msgsnd","munlock","munlockall","nanosleep","nfsservctl","nice","oldfstat",
"oldlstat","oldolduname","oldstat","olduname","pause","pciconfig_iobase","pciconfig_read","pciconfig_write",
"perf_event_open","in","personality","phys","pipe","pipe2","pivot_root","poll",
"ppoll","prctl","renamed","prlimit","prof","profil",
"pselect6","ptrace","putpmsg","query_module","quotactl","readahead","readdir",
"readlink","readlinkat","reboot",
"request_key","restart_syscall","rt_sigaction","rt_sigpending","rt_sigprocmask","rt_sigqueueinfo","rt_sigreturn",
"rt_sigsuspend","rt_sigtimedwait","rt_tgsigqueueinfo","sched_get_priority_max","sched_get_priority_min","sched_getaffinity","sched_getparam","sched_getscheduler",
"sched_rr_get_interval","sched_setaffinity","sched_setparam","sched_setscheduler","sched_yield","security","select","semctl",
"semget","semop","semtimedop",
"set_mempolicy","set_robust_list","set_thread_area","set_tid_address","set_zone_reclaim","available","setdomainname","setfsgid",
"setfsgid32","setfsuid","setfsuid32","setgid","setgid32","setgroups","setgroups32","sethostname",
"setitimer","setpgid","setpriority","setregid","setregid32","setresgid","setresgid32","setresuid",
"setresuid32","setreuid","setreuid32","setrlimit","setsid","setsockopt","settimeofday","setuid",
"setuid32","setup","sgetmask","shutdown","sigaction","sigaltstack","signal",
"signalfd","signalfd4","sigpending","sigprocmask","sigreturn","sigsuspend","socketcall",
"spu_create","spu_run","ssetmask","stat","stat64","statfs","statfs64",
"stime","stty","subpage_prot","swapoff","swapon","sysfs","sysinfo","syslog",
"tgkill","time","timer_create","timer_delete","timer_getoverrun","timer_gettime","timer_settime","timerfd_create",
"timerfd_gettime","timerfd_settime","times","tkill","tuxcall","ugetrlimit","ulimit",
"uname","unshare","uselib","ustat","utime","utimensat","utimes",
"vhangup","vm86old","vserver","wait4","waitid","waitpid", "mount", "fstatat", "newfstatat", 
"syscall_317", "syscall_999", "syscall_318"]

innocent_syscalls += ['mtrace_mmap', 'mtrace_munmap', 'mtrace_thread_start']
innocent_net_calls = ['setsockopt','getsockopt','getsockname','shutdown', 'getpeername']
interesting_net_calls = ['socket','bind','connect','listen','accept','socketpair','send','recv',
'sendto','recvfrom','sendmsg','recvmsg','accept4','recvmmsg','sendmmsg', 'sendfile']

# Some system calls have special 64-bit versions. The 64-bit versions
# are not inherently different from the original versions, and strace
# automatically converts their representation to look like the original.
equivalent_syscall = {}
equivalent_syscall['pwrite64'] = 'pwrite'
equivalent_syscall['_llseek'] = 'lseek'
equivalent_syscall['ftruncate64'] = 'ftruncate'

sync_ops = set(['fsync', 'fdatasync', 'file_sync_range', 'sync'])
expansive_ops = set(['append', 'trunc', 'write', 'unlink', 'rename'])
pseudo_ops = sync_ops | set(['stdout'])
real_ops = expansive_ops | set(['creat', 'link', 'mkdir', 'rmdir'])
connection_manager = None
well_known_ports = None
can_die_at = ['+++ killed by', '+++ exited with', ' --- SIG', '<unfinished ...>', ' = ? <unavailable>', 'ptrace(SYSCALL):No such process', 'wait4', 'poll', 'futex', 'msync', 'accept', 'connect', 'nanosleep', 'rt_sigprocma', 'timerfd_settime', 'fdatasync', 'select']
die_active = ['read', 'recvmsg']
can_die_at += die_active

class ConnectionManager:
	def __init__(self, address_map):
		self.machine_address_map = address_map		
		self.connected_socket_ends = defaultdict(list)

	def machine_id_for_address(self, address):
		for machine in self.machine_address_map:
			if address in self.machine_address_map[machine]:
				return machine

	def is_interesting_ip(self, ip):
		return (ip in self.machine_address_map.values())

	def addresses_for_machine_id(self, machine_id):
		return self.machine_address_map[machine_id]

	def connect_server_to_client(self, server_host, server_port, client_host, client_port, accept_time):
		assert type(server_port) == int
		assert type(client_port) == int
		assert type(accept_time) == float
		self.connected_socket_ends[(server_host, server_port)].append((client_host, client_port, accept_time))

	def connected_ends(self, server_host, server_port, client_host, client_port, connect_time, toprint = False):
		assert type(server_port) == int
		possible_candidates_all = self.connected_socket_ends[(server_host, server_port)]
		toret = [None]
		min_delta = sys.float_info.max
		possible_candidates = [p for p in possible_candidates_all if p[0] == client_host and p[1] == client_port]		
		
		# We should be able to deterministically associate the accept and the connect system calls
		# on two different machines
		assert len(possible_candidates) <= 1 

		if toprint:
			print 'Possible socket candidates:' + str(possible_candidates)
		for candidate in possible_candidates:
			toret[0] = candidate
	
		return toret
		
def parse_line(line):
	try:			
		toret = Struct()
		# Split the line, the format being 'HH:MM:SS.nnnnn syscall(args...) = RETVALUE ERRORCODE (Error String)'
		# Bit afraid to change the working regex parsing, So cut off the duration part separately
		
		duration = None
		duration_start = None
		duration_end = None
		duration_ex = False
		try:
			duration_end = line.rindex('>')
			duration_start = line.rindex('<') + 1
			duration = line[duration_start:duration_end]
			duration = float(duration)
		except ValueError:
			duration_ex = True
			if (duration_end is not None or duration_start is not None):
				if not '...' in duration and not 'unavailable' in duration and not 'ptrace(SYSCALL):No such process' in duration:
					assert False

		if not duration_ex:
			line = line[0:duration_start-1].rstrip()
		
		m = re.search(r'^([0-9:\.]+) ([^(]+)(\(.*\)) += ([xa-f\-0-9]+|\?) ?(E[^ ]* \([^\(\)]*\)|\([^\(\)]*\))?$', line)

		# Convert time into a numerical value
		time = line[m.start(1) : m.end(1)]
		toret.str_time = time + "+" + str(duration)
		time = time.split(':')
		toret.time = int(time[0]) * 60.0 * 60.0 + int(time[1]) * 60.0 + float(time[2])
		
		toret.syscall = line[m.start(2) : m.end(2)]
		toret.ret = line[m.start(4) : m.end(4)]
		toret.duration = duration

		# toret.time is in seconds.
		# Add duration of the system call in seconds to this time
		# For clone and fork give their starting times - sometimes strace reports spurious times
		if duration is not None and toret.syscall not in ['clone', 'fork', 'vfork']:	
			toret.time += duration
			
		return_explanation = line[m.start(5) : m.end(5)]
		if return_explanation.startswith("E"):
			toret.err = return_explanation
		else:
			toret.return_explanation = return_explanation

		# The arguments part looks something like '(20, "hello", "world", 3)'
		args = csv.reader([line[m.start(3):m.end(3)]], delimiter=',', quotechar='"').next()
		# Now args is ['(20', ' "hello"', ' "world"', ' 3)']
		args = [x[1:] for x in args]
		args[len(args) - 1] = args[len(args) - 1][:-1]
		toret.args = args

		return toret
	except AttributeError as err:
		for innocent_line in can_die_at:
			if line.find(innocent_line) != -1:
				return False
		print line
		raise err

class MemregionTracker:
	def __init__(self):
		# memregion_map[addr_start] = Struct(addr_end, name, inode, offset)
		self.memregion_map = {}

	def __find_overlap(self, addr_start, addr_end, return_immediately = True):
		toret = []
		for cur_start in self.memregion_map.keys():
			memregion = self.memregion_map[cur_start]
			cur_end = memregion.addr_end
			if (addr_start >= cur_start and addr_start <= cur_end) or \
				(addr_end >= cur_start and addr_end <= cur_end) or \
				(cur_start >= addr_start and cur_start <= addr_end) or \
				(cur_end >= addr_start and cur_end <= addr_end):
				if return_immediately:
					return memregion
				else:
					toret.append(memregion)
		if return_immediately:
			return False
		return toret

	
	def insert(self, addr_start, addr_end, name, inode, offset):
		assert self.__find_overlap(addr_start, addr_end) == False
		self.memregion_map[addr_start] = Struct(addr_start = addr_start, addr_end = addr_end, name = name, inode = inode, offset = offset)

	def remove_overlaps(self, addr_start, addr_end, whole_regions = False):
		while True:
			found_region = self.__find_overlap(addr_start, addr_end)
			if found_region == False:
				return

			found_region = copy.deepcopy(found_region)
			del self.memregion_map[found_region.addr_start]

			if not whole_regions:
				if(found_region.addr_start < addr_start):
					new_region = copy.deepcopy(found_region)
					new_region.addr_end = addr_start - 1
					self.memregion_map[new_region.addr_start] = new_region
				if(found_region.addr_start > addr_end):
					new_region = copy.deepcopy(found_region)
					new_region.addr_start = addr_end + 1
					new_region.offset = (new_region.addr_start - found_region.addr_start) + found_region.offset
					self.memregion_map[new_region.addr_start] = new_region

	def file_mapped(self, inode):
		for region in self.memregion_map.values():
			if region.inode == inode:
				return True
		return False

	def resolve_range(self, addr_start, addr_end):
		toret = []
		overlap_regions = copy.deepcopy(self.__find_overlap(addr_start, addr_end, return_immediately = False))
		overlap_regions = sorted(overlap_regions, key = lambda region: region.addr_start)
		for region in overlap_regions:
			if region.addr_start < addr_start:
				assert addr_start <= region.addr_end
				region.offset = (addr_start - region.addr_start) + region.offset
				region.addr_start = addr_start
			if region.addr_end > addr_end:
				assert addr_end >= region.addr_start
				region.addr_end = addr_end
			assert region.addr_start >= addr_start
			assert region.addr_end <= addr_end
			toret.append(region)
		return toret

class FileDescriptorTracker:
	def __init__(self):
		self.fd_details = {}

	def new_fd_mapping(self, fd, name, pos, attribs, inode):
		if fd in self.fd_details:
			print self.fd_details[fd]
		assert fd not in self.fd_details
		attribs = set(attribs)
		self.fd_details[fd] = Struct(name = name, pos = pos, attribs = attribs, inode = inode)

	def set_equivalent(self, oldfd, newfd):
		assert oldfd in self.fd_details
		assert newfd not in self.fd_details
		self.fd_details[newfd] = self.fd_details[oldfd]

	def remove_fd_mapping(self, fd):
		assert fd in self.fd_details
		del self.fd_details[fd]

	def is_watched(self, fd):
		return (fd in self.fd_details)

	def get_pos(self, fd):
		assert fd in self.fd_details
		return self.fd_details[fd].pos

	def get_inode(self, fd):
		assert fd in self.fd_details
		return self.fd_details[fd].inode

	def get_attribs(self, fd):
		assert fd in self.fd_details
		return self.fd_details[fd].attribs

	def set_pos(self, fd, pos):
		assert fd in self.fd_details
		self.fd_details[fd].pos = pos

	def get_name(self, fd):
		assert fd in self.fd_details
		return self.fd_details[fd].name

	def get_fds_fname(self, name):
		result = [fd for fd in self.fd_details if self.fd_details[fd].name == name]
		return result

	def get_fds(self, inode):
		result = [fd for fd in self.fd_details if self.fd_details[fd].inode == inode]
		return result

	def get_fds_attribs(self, attrib):
		toret = []
		for fd in self.fd_details:
			if attrib in self.fd_details[fd].attribs:
				toret.append(fd)
		return toret

	def set_new_name(self, fd, new_name):
		self.fd_details[fd].name = new_name

class SocketDescriptorTracker:
	def __init__(self):
		self.sfd_details = {}

	def new_sfd_mapping(self, sfd, name, server_host, server_port, client_host, client_port, attribs):
		assert attribs is not None
		if server_port is not None:
			assert type(server_port) == int
		if client_port is not None:
			assert type(client_port) == int
		attribs = set(attribs)
		
		if sfd in self.sfd_details:
			print self.sfd_details[sfd]
		
		self.sfd_details[sfd] = Struct(name = name, server_host = server_host, server_port = server_port, \
									client_host = client_host, client_port = client_port, attribs = attribs)

	def set_equivalent(self, oldfd, newfd):
		assert oldfd in self.sfd_details
		assert newfd not in self.sfd_details
		self.sfd_details[newfd] = self.sfd_details[oldfd]

	def remove_sfd_mapping(self, sfd):
		assert sfd in self.sfd_details
		del self.sfd_details[sfd]

	def is_watched(self, sfd):
		return (sfd in self.sfd_details)

	def get_server_host(self, sfd):
		assert sfd in self.sfd_details
		return self.sfd_details[sfd].server_host

	def get_client_host(self, sfd):
		assert sfd in self.sfd_details
		return self.sfd_details[sfd].client_host

	def get_name(self, sfd):
		assert sfd in self.sfd_details
		return self.sfd_details[sfd].name

	def get_server_port(self, sfd):
		assert sfd in self.sfd_details
		return self.sfd_details[sfd].server_port

	def get_socket_struct(self, sfd):
		assert sfd in self.sfd_details
		return self.sfd_details[sfd]

	def get_client_port(self, sfd):
		assert sfd in self.sfd_details
		return self.sfd_details[sfd].client_port

	def get_attribs(self, fd):
		assert fd in self.sfd_details
		return self.sfd_details[fd].attribs

	def get_fds_attribs(self, attrib):
		toret = []
		for fd in self.sfd_details:
			if attrib in self.sfd_details[fd].attribs:
				toret.append(fd)
		return toret

	def set_server_host_and_port(self, sfd, server_host, server_port):
		assert sfd in self.sfd_details
		assert type(server_port) == int
		self.sfd_details[sfd].server_host = server_host
		self.sfd_details[sfd].server_port = server_port

	def set_client_host_and_port(self, sfd, client_host, client_port):
		assert sfd in self.sfd_details
		assert type(client_port) == int
		self.sfd_details[sfd].client_host = client_host
		self.sfd_details[sfd].client_port = client_port

def __replayed_stat(machine_id, path):
	try:
		return os.stat(replayed_path(machine_id, path))
	except OSError as err:
		return False

def __parent_inode(machine_id, path):
	return __replayed_stat(machine_id, os.path.dirname(path)).st_ino

def __replayed_truncate(machine_id, path, new_size):
	old_mode = writeable_toggle(replayed_path(machine_id, path))
	tmp_fd = os.open(replayed_path(machine_id, path), os.O_WRONLY)
	os.ftruncate(tmp_fd, new_size)
	os.close(tmp_fd)
	writeable_toggle(replayed_path(machine_id, path), old_mode)

def __get_files_from_inode(machine_id, inode, all_files = False):
	if not all_files:
		results = subprocess.check_output(['find', paceconfig(machine_id).scratchpad_dir, '-inum', str(inode)])
	else:
		assert inode == 0
		results = subprocess.check_output(['find', paceconfig(machine_id).scratchpad_dir])
	toret = []
	for path in results.split('\n'):
		if path != '':
			# Converting the (replayed) path into original path
			assert path.startswith(paceconfig(machine_id).scratchpad_dir)
			path = path.replace(paceconfig(machine_id).scratchpad_dir, paceconfig(machine_id).base_path + '/', 1)
			path = re.sub(r'//', r'/', path)

			assert __replayed_stat(machine_id, path)
			if not all_files:
				assert __replayed_stat(machine_id, path).st_ino == inode
			toret.append(path)
	return toret

class ProcessTracker:
	def __init__(self, machine_id, pid):
		self.machine_id = machine_id
		self.pid = pid
		self.memtracker = MemregionTracker()
		self.fdtracker = FileDescriptorTracker()
		self.socktracker = SocketDescriptorTracker()
		self.fdtracker_unwatched = FileDescriptorTracker()
		self.socktracker_unwatched = SocketDescriptorTracker()
		self.cwd = paceconfig(machine_id).starting_cwd 
		self.child_tids = []

	def record_fork(self, machine_id, forked_tid):
		assert (machine_id, forked_tid) not in ProcessTracker.trackers_map
		toret = copy.deepcopy(self)
		toret.pid = forked_tid
		toret.child_tids = []
		ProcessTracker.trackers_map[(machine_id, forked_tid)] = toret
	
	def record_clone(self, machine_id, cloned_tid):
		assert (machine_id, cloned_tid) not in ProcessTracker.trackers_map
		self.child_tids.append(cloned_tid)
		ProcessTracker.trackers_map[(machine_id, cloned_tid)] = self

	def record_execve(self, machine_id):
		fds_to_remove = self.fdtracker.get_fds_attribs('O_CLOEXEC')
		socks_to_remove = self.socktracker.get_fds_attribs('O_CLOEXEC')
		for fd in fds_to_remove:
			self.fdtracker.remove_fd_mapping(fd)

		for sock in socks_to_remove:
			self.socktracker.remove_sfd_mapping(sock)

		fds_to_remove = self.fdtracker_unwatched.get_fds_attribs('O_CLOEXEC')
		socks_to_remove = self.socktracker_unwatched.get_fds_attribs('O_CLOEXEC')
		for fd in fds_to_remove:
			self.fdtracker_unwatched.remove_fd_mapping(fd)

		for sock in socks_to_remove:
			self.socktracker_unwatched.remove_sfd_mapping(sock)

		self.memtracker = MemregionTracker()

		for child_tid in self.child_tids:
			ProcessTracker.trackers_map[(machine_id, child_tid)] = None
		self.child_tids = []


	def set_cwd(self, path):
		self.cwd = path

	def original_path(self, path):
		if not path.startswith('/'):
			path = self.cwd + '/' + path
		while True:
			old_path = path
			path = re.sub(r'//', r'/', path)
			path = re.sub(r'/\./', r'/', path)
			path = re.sub(r'/[^/]*/\.\./', r'/', path)
			if path == old_path:
				break
		return path

	trackers_map = {} ## trackers_map[pid] = (memtracker, fdtracker, socktracker, proctracker)
	@staticmethod
	def get_proctracker(machine_id, tid):
		if (machine_id, tid) not in ProcessTracker.trackers_map:
			# Pid corresponds to a process that was created directly from the workload.
			# i.e., not forked from anywhere
			ProcessTracker.trackers_map[(machine_id, tid)] = ProcessTracker(machine_id, tid)
		toret = ProcessTracker.trackers_map[(machine_id, tid)]
		assert toret.machine_id == machine_id
		assert toret.pid == tid or tid in toret.child_tids
		return toret
	
	@staticmethod
	def trackers_for_machine(machine_id):
		toret = []
		for tracker in ProcessTracker.trackers_map:
			if tracker[0] == machine_id:
				toret.append(ProcessTracker.trackers_map[tracker])	
		return toret

symtab = None
SymbolTableEntry = namedtuple('SymbolTableEntry',
	['func_name', 'instr_offset', 'src_filename', 'src_line_num'])
StackEntry = namedtuple('StackEntry',
	['func_name', 'instr_offset', 'src_filename', 'src_line_num',
	'binary_filename', 'addr_offset', 'raw_addr'])
def __get_backtrace(stackinfo):
	global symtab
	backtrace = []

	if paceconfig(0).ignore_stacktrace: return backtrace

	assert stackinfo[0] == '['
	assert stackinfo[-2] == ']'
	stackinfo = stackinfo[1:-2].strip()

	if stackinfo == '':
		return []

	stack_addrs_lst = stackinfo.split()
	for addr in stack_addrs_lst:
		binary_filename, addr_offset, raw_addr = addr.split(':')
		symtab_for_file = symtab[binary_filename]

		# try both addr_offset and raw_addr to see if either one matches:
		if addr_offset in symtab_for_file:
			syms = SymbolTableEntry._make(symtab_for_file[addr_offset])
		elif raw_addr in symtab_for_file:
			syms = SymbolTableEntry._make(symtab_for_file[raw_addr])
		else:
			syms = SymbolTableEntry(None, None, None, None)

		assert len(syms) == 4
		t = StackEntry(syms.func_name, syms.instr_offset, syms.src_filename, syms.src_line_num,\
					 binary_filename, addr_offset, raw_addr)
		backtrace.append(t)

	return backtrace

__directory_symlinks = []

def __socket_parser(machine_id, parsed_line):
	toret_host = None
	toret_port = None
	port_property_name = 'sin_port'
	s_family = -1
	for arg in parsed_line.args:								
		if 'sa_family' in arg:
			socket_family = arg.split('=')[1].replace('}', '').replace('{','').replace('htons','').replace('(', '').replace(')','')
			if socket_family == 'AF_INET6' or socket_family == 'PF_INET6':
				s_family = 6
				port_property_name = 'sin6_port'
			else:
				s_family = 4
		if port_property_name in arg:
			toret_port = arg.split('=')[1].replace('}', '').replace('{','').replace('htons','').replace('(', '').replace(')','')
		
		if s_family == 4:
			if 'sin_addr' in arg:
				toret_host = arg.split('=')[1].replace('}', '').replace('{','').replace('inet_addr','').replace('(', '').replace(')','').replace('\"','')
		elif s_family == 6:
			if 'ffff' in arg:
				# This is a shameless hack to get the ipv4 address from the traces. 
				# Works for all systems that we study
				toret_host = arg.replace('ffff','').replace(':','')
			elif '\"::\"' == arg:
				# This is a bad hack to fill in the host address but works atleast for all systems we study
				machine_addresses = connection_manager.addresses_for_machine_id(machine_id)
				toret_host = machine_addresses
			else:
				if toret_host is None:
					toret_host = 'NOT_KNOWN'

	if toret_host is not None:
		toret_host = toret_host.replace('\"','').replace('\'', '')

	return (toret_host, toret_port)
		
def __get_micro_op(machine_id, syscall_tid, line, stackinfo, mtrace_recorded):	
	micro_operations = []
	assert type(syscall_tid) == int
	proctracker = ProcessTracker.get_proctracker(machine_id, syscall_tid) 
	memtracker = proctracker.memtracker
	fdtracker = proctracker.fdtracker
	socktracker = proctracker.socktracker
	fdtracker_unwatched = proctracker.fdtracker_unwatched
	socktracker_unwatched = proctracker.socktracker_unwatched

	global __directory_symlinks
	parsed_line = parse_line(line)

	if parsed_line == False:
		return []

	### Known Issues:
	###	1. Access time with read() kind of calls, modification times in general, other attributes
	###	2. Symlinks

	if parsed_line.syscall == 'open' or parsed_line.syscall == 'openat':
		dirfd = -1
		if parsed_line.syscall == 'openat':
			if not parsed_line.args[0] == 'AT_FDCWD':
				dirfd = safe_string_to_int(parsed_line.args[0])
			parsed_line.args.pop(0)

		flags = parsed_line.args[1].split('|')
		if dirfd > 0:
			dirname = fdtracker.get_name(dirfd)		
			name = os.path.join(dirname, eval(parsed_line.args[0]))
		else:
			name = proctracker.original_path(eval(parsed_line.args[0]))
		
		mode = parsed_line.args[2] if len(parsed_line.args) == 3 else False
		fd = safe_string_to_int(parsed_line.ret);
		if is_interesting(machine_id, name):
			if 'O_WRONLY' in flags or 'O_RDWR' in flags:
				assert 'O_ASYNC' not in flags
				assert 'O_DIRECTORY' not in flags
			if fd >= 0 and 'O_DIRECTORY' not in flags:
				# Finished with most of the asserts and initialization. Actually handling the open() here.

				newly_created = False
				if not __replayed_stat(machine_id, name):
					assert 'O_CREAT' in flags
					assert 'O_WRONLY' in flags or 'O_RDWR' in flags or 'O_RDONLY' in flags
					assert len(fdtracker.get_fds_fname(name)) == 0
					assert mode
					tmp_fd = os.open(replayed_path(machine_id, name), os.O_CREAT | os.O_WRONLY, eval(mode))
					assert tmp_fd > 0
					os.close(tmp_fd)
					inode = __replayed_stat(machine_id, name).st_ino
					new_op = Struct(op = 'creat', name = name, mode = mode, inode = inode, parent = __parent_inode(machine_id, name))
					micro_operations.append(new_op)
					newly_created = True
				else:
					inode = __replayed_stat(machine_id, name).st_ino

				if 'O_TRUNC' in flags:
					assert 'O_WRONLY' in flags or 'O_RDWR' in flags
					if not newly_created:
						new_op = Struct(op = 'trunc', name = name, initial_size = __replayed_stat(machine_id, name).st_size, final_size = 0, inode = inode)
						micro_operations.append(new_op)
						__replayed_truncate(machine_id, name, 0)

				fd_flags = []
				if 'O_SYNC' in flags or 'O_DSYNC' in flags or 'O_RSYNC' in flags:
					fd_flags.append('O_SYNC')
				if 'O_CLOEXEC' in flags:
					fd_flags.append('O_CLOEXEC')

				if 'O_APPEND' in flags:
					fdtracker.new_fd_mapping(fd, name, __replayed_stat(machine_id, name).st_size, fd_flags, inode)
				else:
					fdtracker.new_fd_mapping(fd, name, 0, fd_flags, inode)
			if fd >= 0 and 'O_DIRECTORY' in flags:
				fd_flags = []
				inode = __replayed_stat(machine_id, name).st_ino
				if 'O_SYNC' in flags or 'O_DSYNC' in flags or 'O_RSYNC' in flags:
					fd_flags.append('O_SYNC')
				if 'O_CLOEXEC' in flags:
					fd_flags.append('O_CLOEXEC')

				fdtracker.new_fd_mapping(fd, name, 0, fd_flags, inode)
		elif fd >= 0:
			fd_flags = []
			if 'O_CLOEXEC' in flags:
				fd_flags.append('O_CLOEXEC')
			fdtracker_unwatched.new_fd_mapping(fd, name, 0, fd_flags, 0)
	elif parsed_line.syscall in ['read', 'readv', 'pread', 'preadv']:
		fd = safe_string_to_int(parsed_line.args[0])

		#read can be on a socket
		if socktracker.is_watched(fd):
			sock_fd = safe_string_to_int(parsed_line.args[0])
			recvd_data_size = safe_string_to_int(parsed_line.ret)
			#for now ignore the sockaddr struct. Assume everyone does connect and then send
			server_host = socktracker.get_server_host(sock_fd)
			server_port = socktracker.get_server_port(sock_fd)
			client_host = socktracker.get_client_host(sock_fd)
			client_port = socktracker.get_client_port(sock_fd)

			assert type(server_port) == int
			assert type(client_port) == int
			
			assert server_host is not None and server_port != -1
			assert client_host is not None and client_port != -1

			if socktracker.is_watched(sock_fd):
				if recvd_data_size > 0:
					new_op = Struct(op = 'recv', name = socktracker.get_name(sock_fd), size = recvd_data_size,\
								 server_host = server_host, server_port = server_port, client_host = client_host,\
								 client_port = client_port, has_cross_deps = True, remaining = recvd_data_size)
					micro_operations.append(new_op)

		else:
			if not paceconfig(machine_id).ignore_file_read:
				name = None
				if fdtracker_unwatched.is_watched(fd):
					name = fdtracker_unwatched.get_name(fd)
				elif fdtracker.is_watched(fd):
					name = fdtracker.get_name(fd)

				try:
					if is_interesting(machine_id, name):
						dump_file = eval(parsed_line.args[-2])
						dump_offset = safe_string_to_int(parsed_line.args[-1])
						
						if parsed_line.syscall == 'read':
							count = safe_string_to_int(parsed_line.args[2])
							pos = fdtracker.get_pos(fd)
						elif parsed_line.syscall == 'readv':
							count = safe_string_to_int(parsed_line.args[3])
							pos = fdtracker.get_pos(fd)
						elif parsed_line.syscall == 'pread':
							count = safe_string_to_int(parsed_line.args[2])
							pos = safe_string_to_int(parsed_line.args[3])
						elif parsed_line.syscall == 'preadv':
							count = safe_string_to_int(parsed_line.args[4])
							pos = safe_string_to_int(parsed_line.args[3])
						
						new_op = Struct(op = 'read', name = name , mode = None, dump_file = dump_file, dump_offset = dump_offset)
						micro_operations.append(new_op)
						fdtracker.set_pos(fd, pos + count)
				except:
					pass
	elif parsed_line.syscall in ['write', 'writev', 'pwrite', 'pwritev']:	
		fd = safe_string_to_int(parsed_line.args[0])
		
		if socktracker.is_watched(fd):
			assert parsed_line.syscall == 'write' or parsed_line.syscall == 'writev'

			sock_fd = safe_string_to_int(parsed_line.args[0])
			send_data_size = safe_string_to_int(parsed_line.ret)
			dump_file = eval(parsed_line.args[-2])
			dump_offset = safe_string_to_int(parsed_line.args[-1])
			
			server_host = socktracker.get_server_host(sock_fd)
			server_port = socktracker.get_server_port(sock_fd)
			client_host = socktracker.get_client_host(sock_fd)
			client_port = socktracker.get_client_port(sock_fd)

			assert type(server_port) == int
			assert type(client_port) == int
			
			assert server_host is not None and server_port != -1
			assert client_host is not None and client_port != -1

			if socktracker.is_watched(sock_fd):
				if send_data_size > 0:
					new_op = Struct(op = 'send', name = str(socktracker.get_name(sock_fd)), size = send_data_size,\
								 dump_file = dump_file, dump_offset = dump_offset, server_host = server_host,\
								 server_port = server_port, client_host = client_host, client_port = client_port, remaining = send_data_size)
					micro_operations.append(new_op)
		else:	
			name = None
			if fdtracker_unwatched.is_watched(fd):
				name = fdtracker_unwatched.get_name(fd)
			elif fdtracker.is_watched(fd):
				name = fdtracker.get_name(fd)
			if fdtracker.is_watched(fd) or fd == 1:
				dump_file = eval(parsed_line.args[-2])
				dump_offset = safe_string_to_int(parsed_line.args[-1])
				if fd == 1:
					count = safe_string_to_int(parsed_line.args[2])
					fd_data = os.open(dump_file, os.O_RDONLY)
					os.lseek(fd_data, dump_offset, os.SEEK_SET)
					buf = os.read(fd_data, count)
					os.close(fd_data)
					if buf.startswith(paceconfig(machine_id).interesting_stdout_prefix):
						new_op = Struct(op = 'stdout', data = buf)
						micro_operations.append(new_op)
				else:
					if parsed_line.syscall == 'write':
						count = safe_string_to_int(parsed_line.args[2])
						pos = fdtracker.get_pos(fd)
					elif parsed_line.syscall == 'writev':
						count = safe_string_to_int(parsed_line.args[3])
						pos = fdtracker.get_pos(fd)
					elif parsed_line.syscall == 'pwrite':
						count = safe_string_to_int(parsed_line.args[2])
						pos = safe_string_to_int(parsed_line.args[3])
					elif parsed_line.syscall == 'pwritev':
						count = safe_string_to_int(parsed_line.args[4])
						pos = safe_string_to_int(parsed_line.args[3])
					assert safe_string_to_int(parsed_line.ret) == count
					name = fdtracker.get_name(fd)
					inode = fdtracker.get_inode(fd)
					size = __replayed_stat(machine_id, name).st_size
					overwrite_size = 0
					if pos < size:
						if pos + count < size:
							overwrite_size = count
						else:
							overwrite_size = size - pos
						new_op = Struct(op = 'write', name = name, offset = pos, count = overwrite_size, dump_file = dump_file, dump_offset = dump_offset, inode = inode)
						assert new_op.count > 0
						micro_operations.append(new_op)
						if 'O_SYNC' in fdtracker.get_attribs(fd):
							new_op = Struct(op = 'file_sync_range', name = name, offset = pos, count = overwrite_size, inode = inode)
							micro_operations.append(new_op)
					pos += overwrite_size
					count -= overwrite_size
					dump_offset += overwrite_size
	
					if(pos > size):
						new_op = Struct(op = 'trunc', name = name, final_size = pos, inode = inode, initial_size = size)
						micro_operations.append(new_op)
						__replayed_truncate(machine_id, name, size)
						size = pos
	
					if(pos + count > size):
						new_op = Struct(op = 'append', name = name, offset = pos, count = count, dump_file = dump_file, dump_offset = dump_offset, inode = inode)
						micro_operations.append(new_op)
						__replayed_truncate(machine_id, name, pos + count)
	
						if 'O_SYNC' in fdtracker.get_attribs(fd):
							new_op = Struct(op = 'file_sync_range', name = name, offset = pos, count = count, inode = inode)
							micro_operations.append(new_op)
					if parsed_line.syscall not in ['pwrite', 'pwritev']:
						fdtracker.set_pos(fd, pos + count)
	elif parsed_line.syscall == 'close':
		if int(parsed_line.ret) == -1:
			if paceconfig(machine_id).debug_level >= 2:
				print 'WARNING: close() returned -1. ' + line
		else:
			fd = safe_string_to_int(parsed_line.args[0])
			if fdtracker.is_watched(fd):
				fdtracker.remove_fd_mapping(fd)
			else:
				if fdtracker_unwatched.is_watched(fd):
					fdtracker_unwatched.remove_fd_mapping(fd)
					
			if socktracker.is_watched(fd):
				socktracker.remove_sfd_mapping(fd)
			else:
				if socktracker_unwatched.is_watched(fd):
					socktracker_unwatched.remove_sfd_mapping(fd)
	elif parsed_line.syscall == 'link':
		if int(parsed_line.ret) != -1:
			source = proctracker.original_path(eval(parsed_line.args[0]))
			dest = proctracker.original_path(eval(parsed_line.args[1]))
			if is_interesting(machine_id, source):
				assert is_interesting(machine_id, dest)
				assert not __replayed_stat(machine_id, dest)
				assert __replayed_stat(machine_id, source)
				source_inode = __replayed_stat(machine_id, source).st_ino
				micro_operations.append(Struct(op = 'link', source = source, dest = dest, source_inode = source_inode, source_parent = __parent_inode(machine_id, source), dest_parent = __parent_inode(machine_id, dest)))
				os.link(replayed_path(machine_id, source), replayed_path(machine_id, dest))
			else:
				assert not is_interesting(machine_id, dest)	
	elif parsed_line.syscall == 'rename' or parsed_line.syscall == 'renameat':
		if int(parsed_line.ret) != -1:			
			new_dirname = old_dirname = None
			if parsed_line.syscall == 'renameat':
				if not parsed_line.args[0] == 'AT_FDCWD':
					old_dirname = fdtracker.get_name(safe_string_to_int(parsed_line.args[0]))
					assert old_dirname is not None
				parsed_line.args.pop(0)
				if not parsed_line.args[1] == 'AT_FDCWD':
					new_dirname = fdtracker.get_name(safe_string_to_int(parsed_line.args[1]))
					assert new_dirname is not None
				parsed_line.args.pop(1)
					
			assert (new_dirname is None and old_dirname is None) or (new_dirname is not None and old_dirname is not None)
			if new_dirname is not None and old_dirname is not None:
				source = os.path.join(old_dirname, eval(parsed_line.args[0]))
				dest = os.path.join(old_dirname, eval(parsed_line.args[1]))
			else:
				source = proctracker.original_path(eval(parsed_line.args[0]))
				dest = proctracker.original_path(eval(parsed_line.args[1]))
				
			if is_interesting(machine_id, source):
				assert is_interesting(machine_id, dest)
				assert __replayed_stat(machine_id, source)
				source_inode = __replayed_stat(machine_id, source).st_ino
				source_hardlinks = __replayed_stat(machine_id, source).st_nlink
				source_size = __replayed_stat(machine_id, source).st_size
				dest_inode = False
				dest_hardlinks = 0
				dest_size = 0
				if __replayed_stat(machine_id, dest):
					dest_inode = __replayed_stat(machine_id, dest).st_ino
					dest_hardlinks = __replayed_stat(machine_id, dest).st_nlink
					dest_size = __replayed_stat(machine_id, dest).st_size
				micro_operations.append(Struct(op = 'rename', source = source, dest = dest, source_inode = source_inode, dest_inode = dest_inode, source_parent = __parent_inode(machine_id, source), dest_parent = __parent_inode(machine_id, dest), source_hardlinks = source_hardlinks, dest_hardlinks = dest_hardlinks, dest_size = dest_size, source_size = source_size))
				if dest_hardlinks == 1:
					if not len(fdtracker.get_fds(dest_inode)) == 0:
						fd = fdtracker.get_fds(source_inode)[0]
						fdtracker.set_new_name(int(fd), dest)
					else:
						assert len(fdtracker.get_fds(dest_inode)) == 0
					assert memtracker.file_mapped(dest_inode) == False
					os.rename(replayed_path(machine_id, dest), replayed_path(machine_id, dest) + '.deleted_' + str(uuid.uuid1()))
				os.rename(replayed_path(machine_id, source), replayed_path(machine_id, dest))
	elif parsed_line.syscall == 'unlink' or parsed_line.syscall == 'unlinkat':
		if int(parsed_line.ret) != -1:
			dirfd = -1
			dirname = None
			if parsed_line.syscall == 'unlinkat':
				if not parsed_line.args[0] == 'AT_FDCWD':
					dirfd = safe_string_to_int(parsed_line.args[0])
				parsed_line.args.pop(0)

				if dirfd > 0:
					dirname = fdtracker.get_name(dirfd)		

				assert parsed_line.args[1] == '0'
				parsed_line.args.pop(1)
				
			if dirfd > 0:
				assert dirname is not None
				name = os.path.join(dirname, eval(parsed_line.args[0]))
			else:
				name = proctracker.original_path(eval(parsed_line.args[0]))
				
			if is_interesting(machine_id, name):
				assert __replayed_stat(machine_id, name)
				inode = __replayed_stat(machine_id, name).st_ino
				if os.path.isdir(replayed_path(machine_id, name)):
					assert inode in __directory_symlinks
					micro_operations.append(Struct(op = 'rmdir', name = name, inode = inode, parent = __parent_inode(machine_id, name)))
					os.rename(replayed_path(machine_id, name), replayed_path(machine_id, name) + '.deleted_' + str(uuid.uuid1()))
				else:
					hardlinks = __replayed_stat(machine_id, name).st_nlink
					size = __replayed_stat(machine_id, name).st_size
					micro_operations.append(Struct(op = 'unlink', name = name, inode = inode, hardlinks = hardlinks, parent = __parent_inode(machine_id, name), size = size))
					# A simple os.unlink might be sufficient, but making sure that the inode is not re-used.
					if hardlinks > 1:
						os.unlink(replayed_path(machine_id, name))
						if len(fdtracker.get_fds(inode)) > 1:
							print "Warning: File unlinked while being open: " + name
						if memtracker.file_mapped(inode):
							print "Warning: File unlinked while being mapped: " + name
					else:
						os.rename(replayed_path(machine_id, name), replayed_path(machine_id, name) + '.deleted_' + str(uuid.uuid1()))
	elif parsed_line.syscall == 'lseek':
		if int(parsed_line.ret) != -1:
			fd = safe_string_to_int(parsed_line.args[0])
			if fdtracker.is_watched(fd):
				fdtracker.set_pos(fd, int(parsed_line.ret))
	elif parsed_line.syscall in ['truncate', 'ftruncate']:
		assert int(parsed_line.ret) != -1
		if parsed_line.syscall == 'truncate':
			name = proctracker.original_path(eval(parsed_line.args[0]))
			interesting = is_interesting(machine_id, name)
			if interesting:
				assert __replayed_stat(machine_id, name)
				inode = __replayed_stat(machine_id, name).st_ino
				init_size = __replayed_stat(machine_id, name).st_size
		else:
			fd = safe_string_to_int(parsed_line.args[0])
			interesting = fdtracker.is_watched(fd)
			if interesting:
				name = fdtracker.get_name(fd)
				inode = fdtracker.get_inode(fd)
				files = __get_files_from_inode(machine_id = machine_id, inode = inode)
				assert len(files) > 0
				init_size = __replayed_stat(machine_id, files[0]).st_size
		if interesting:
			size = safe_string_to_int(parsed_line.args[1])
			if init_size == size:
				print line
				return []
			new_op = Struct(op = 'trunc', name = name, final_size = size, inode = inode, initial_size = init_size)
			micro_operations.append(new_op)
			__replayed_truncate(machine_id, name, size)
	elif parsed_line.syscall == 'fallocate':
		if int(parsed_line.ret) != -1:
			fd = safe_string_to_int(parsed_line.args[0])
			dump_file = eval(parsed_line.args[-2])
			if fdtracker.is_watched(fd):
				name = fdtracker.get_name(fd)
				mode = parsed_line.args[1]
				#means FALLOC_FL_KEEP_SIZE is specified - If size were changed, we may need to replay
				if mode == '1' or mode == '01':
					return []
				assert mode == '0' 
				offset = safe_string_to_int(parsed_line.args[2])
				count = safe_string_to_int(parsed_line.args[3])
				inode = fdtracker.get_inode(fd)
				init_size = __replayed_stat(machine_id, name).st_size
				if offset + count > init_size:
					new_op = Struct(op = 'trunc', name = name, final_size = offset + count, inode = inode, initial_size = init_size)
					micro_operations.append(new_op)
					__replayed_truncate(machine_id, name, offset + count)				
				# The below line of code is too slow for large preallocates. Hence just dump in a file and mark the dumpfile as is.
				# data = ''.join('0' for x in xrange(count))
				fallocate_dump_file = dump_file		
				os.system('dd if=/dev/zero of='+ fallocate_dump_file + ' bs=' + str(count) + ' count=1')
				new_op = Struct(op = 'write', name = name, inode = inode, offset = offset, count = count, dump_file = fallocate_dump_file, dump_offset = 0, override_data = None)
				assert new_op.count > 0
				micro_operations.append(new_op)
	elif parsed_line.syscall in ['fsync', 'fdatasync']:
		# assert int(parsed_line.ret) == 0 - This assert might not hold for badly written apps
		if int(parsed_line.ret) == 0:
			fd = safe_string_to_int(parsed_line.args[0])
			if fdtracker.is_watched(fd):
				name = fdtracker.get_name(fd)
				inode = fdtracker.get_inode(fd)
				files = __get_files_from_inode(machine_id = machine_id, inode = inode)
				assert len(files) > 0
				size = __replayed_stat(machine_id, files[0]).st_size
				micro_operations.append(Struct(op = parsed_line.syscall, name = name, inode = inode, size = size))
	elif parsed_line.syscall in ['sync']:
		synced_files = []
		for name in __get_files_from_inode(machine_id = machine_id, inode = 0, all_files = True):
			inode = __replayed_stat(machine_id, name).st_ino
			size = __replayed_stat(machine_id, name).st_size
			synced_files.append(Struct(name = name, inode = inode, size = size))
		micro_operations.append(Struct(op = parsed_line.syscall, hidden_files = synced_files))
	elif parsed_line.syscall == 'mkdir':
		if int(parsed_line.ret) != -1:
			name = proctracker.original_path(eval(parsed_line.args[0]))
			mode = parsed_line.args[1]
			if is_interesting(machine_id, name):
				os.mkdir(replayed_path(machine_id, name), eval(mode))
				inode = __replayed_stat(machine_id, name).st_ino
				micro_operations.append(Struct(op = 'mkdir', name = name, mode = mode, inode = inode, parent = __parent_inode(machine_id, name)))
	elif parsed_line.syscall == 'mkdirat':
		if int(parsed_line.ret) != -1:
			assert False #Handle this
	elif parsed_line.syscall == 'rmdir':
		if int(parsed_line.ret) != -1:
			name = proctracker.original_path(eval(parsed_line.args[0]))
			if is_interesting(machine_id, name):
				inode = __replayed_stat(machine_id, name).st_ino
				micro_operations.append(Struct(op = 'rmdir', name = name, inode = inode, parent = __parent_inode(machine_id, name)))
				os.rename(replayed_path(machine_id, name), replayed_path(machine_id, name) + '.deleted_' + str(uuid.uuid1()))
	elif parsed_line.syscall == 'chdir':
		if int(parsed_line.ret) == 0:
			proctracker.set_cwd(proctracker.original_path(eval(parsed_line.args[0])))
	elif parsed_line.syscall == 'fchdir':
		if int(parsed_line.ret) == 0:
			fd = eval(parsed_line.args[0])
			if fdtracker.is_watched(fd):
				name = fdtracker.get_name(fd)
			else:
				assert fdtracker_unwatched.is_watched(fd)
				name = fdtracker_unwatched.get_name(fd)
			proctracker.set_cwd(name)
	elif parsed_line.syscall == 'clone':
		if not hasattr(parsed_line, 'err'):	
			new_tid = int(parsed_line.ret)
			if new_tid != -1:
				flags_string = parsed_line.args[1]
				assert(flags_string.startswith("flags="))
				flags = flags_string[6:].split('|')
				if 'CLONE_VM' in flags:
					assert 'CLONE_FILES' in flags
					assert 'CLONE_FS' in flags
					proctracker.record_clone(machine_id, new_tid)
				else:
					assert 'CLONE_FILES' not in flags
					assert 'CLONE_FS' not in flags
					proctracker.record_fork(machine_id, new_tid)
	elif parsed_line.syscall == 'vfork':
		new_pid = int(parsed_line.ret)
		if new_pid != -1:
			proctracker.record_fork(machine_id, new_pid)
	elif parsed_line.syscall in ['fcntl', 'fcntl64']:
		fd = safe_string_to_int(parsed_line.args[0])
		cmd = parsed_line.args[1]
		assert cmd in ['F_GETFD', 'F_SETFD', 'F_GETFL', 'F_SETFL', 'F_SETLK', 'F_SETLKW', 'F_GETLK', 'F_SETLK64', 'F_SETLKW64', 'F_GETLK64', 'F_DUPFD']

		tracker = None
		if fdtracker.is_watched(fd):
			tracker = fdtracker
		elif fdtracker_unwatched.is_watched(fd):
			tracker = fdtracker_unwatched
		elif socktracker_unwatched.is_watched(fd):
			tracker = socktracker_unwatched
		elif socktracker.is_watched(fd):
			tracker = socktracker

		if tracker:
			if cmd == 'F_SETFD':
				assert parsed_line.args[2] in ['FD_CLOEXEC', '0']
				if parsed_line.args[2] == 'FD_CLOEXEC':
					tracker.get_attribs(fd).add('O_CLOEXEC')
				else:
					tracker.get_attribs(fd).discard('O_CLOEXEC')
			elif cmd == 'F_DUPFD' and eval(parsed_line.ret) != -1:
				new_fd = eval(parsed_line.ret)
				old_fd = eval(parsed_line.args[0])
				tracker.set_equivalent(old_fd, new_fd)
			elif cmd == 'F_SETFL':
				assert tracker == fdtracker_unwatched or tracker == socktracker or tracker == socktracker_unwatched
				if tracker == socktracker:
					assert 'O_RDWR' in parsed_line.args[2] or \
					'O_RDWR|O_NONBLOCK' in parsed_line.args[2] or \
					'O_RDONLY|O_NONBLOCK' in parsed_line.args[2]
	elif parsed_line.syscall in ['mmap', 'mmap2']:
		addr_start = safe_string_to_int(parsed_line.ret)
		length = safe_string_to_int(parsed_line.args[1])
		prot = parsed_line.args[2].split('|')
		flags = parsed_line.args[3].split('|')
		fd = safe_string_to_int(parsed_line.args[4])
		offset = safe_string_to_int(parsed_line.args[5])
		if parsed_line.syscall == 'mmap2':
			offset = offset * 4096

		if addr_start == -1:
			return

		addr_end = addr_start + length - 1
		if 'MAP_FIXED' in flags:
			given_addr = safe_string_to_int(parsed_line.args[0])
			assert given_addr == addr_start
			assert 'MAP_GROWSDOWN' not in flags
			memtracker.remove_overlaps(addr_start, addr_end)

		if 'MAP_ANON' not in flags and 'MAP_ANONYMOUS' not in flags and \
			fdtracker.is_watched(fd) and 'MAP_SHARED' in flags and \
			'PROT_WRITE' in prot:

			name = fdtracker.get_name(fd)
			file_size = __replayed_stat(machine_id, name).st_size
			assert file_size <= offset + length
			if not paceconfig(machine_id).ignore_mmap: assert syscall_tid in mtrace_recorded
			assert 'MAP_GROWSDOWN' not in flags
			memtracker.insert(addr_start, addr_end, fdtracker.get_name(fd), fdtracker.get_inode(fd), offset)
	elif parsed_line.syscall == 'munmap':
		addr_start = safe_string_to_int(parsed_line.args[0])
		length = safe_string_to_int(parsed_line.args[1])
		addr_end = addr_start + length - 1
		ret = safe_string_to_int(parsed_line.ret)
		if ret != -1:
			memtracker.remove_overlaps(addr_start, addr_end, whole_regions = True)
	elif parsed_line.syscall == 'msync':
		addr_start = safe_string_to_int(parsed_line.args[0])
		length = safe_string_to_int(parsed_line.args[1])
		flags = parsed_line.args[2].split('|')
		ret = safe_string_to_int(parsed_line.ret)

		addr_end = addr_start + length - 1
		if ret != -1:
			regions = memtracker.resolve_range(addr_start, addr_end)
			for region in regions:
				count = region.addr_end - region.addr_start + 1
				new_op = Struct(op = 'file_sync_range', name = region.name, inode = region.inode, offset = region.offset, count = count)
				micro_operations.append(new_op)
	elif parsed_line.syscall == 'mwrite':
		addr_start = safe_string_to_int(parsed_line.args[0])
		length = safe_string_to_int(parsed_line.args[2])
		dump_file = eval(parsed_line.args[3])
		dump_offset = safe_string_to_int(parsed_line.args[4])

		addr_end = addr_start + length - 1
		regions = memtracker.resolve_range(addr_start, addr_end)
		for region in regions:
			count = region.addr_end - region.addr_start + 1
			cur_dump_offset = dump_offset + (region.addr_start - addr_start)
			offset = region.offset
			name = region.name
			inode = region.inode
			new_op = Struct(op = 'write', name = name, inode = inode, offset = offset, count = count, dump_file = dump_file, dump_offset = cur_dump_offset)
			assert new_op.count > 0
			micro_operations.append(new_op)
	elif parsed_line.syscall in ['dup', 'dup2', 'dup3']:
		newfd = safe_string_to_int(parsed_line.ret)
		oldfd = safe_string_to_int(parsed_line.args[0])
		if newfd != -1:
			if parsed_line.syscall in ['dup2', 'dup3']:
				if fdtracker.is_watched(newfd):
					fdtracker.remove_fd_mapping(newfd)
				elif fdtracker_unwatched.is_watched(newfd):
					fdtracker_unwatched.remove_fd_mapping(newfd)
				elif socktracker_unwatched.is_watched(newfd):
					socktracker_unwatched.remove_sfd_mapping(newfd)
				elif socktracker.is_watched(newfd):
					socktracker.remove_sfd_mapping(newfd)
			if fdtracker.is_watched(oldfd):
				fdtracker.set_equivalent(oldfd, newfd)
			elif fdtracker_unwatched.is_watched(oldfd):
				fdtracker_unwatched.set_equivalent(oldfd, newfd)
			elif socktracker_unwatched.is_watched(oldfd):
				socktracker_unwatched.set_equivalent(oldfd, newfd)
			elif socktracker.is_watched(oldfd):
				socktracker.set_equivalent(oldfd, newfd)
	elif parsed_line.syscall in ['chmod', 'fchmod', 'chown', 'fchown', 'umask']:
		if parsed_line.syscall.startswith('f'):
			fd = eval(parsed_line.args[0])
			if fdtracker.is_watched(fd):
				print 'WARNING: ' + line + ' :: file = ' + fdtracker.get_name(fd)
		elif parsed_line.syscall == 'umask':
			if not 'umask_warned' in globals():
				globals()['umask_warned'] = True
				print 'WARNING: UMASK'
		else:
			name = proctracker.original_path(eval(parsed_line.args[0]))
			if is_interesting(machine_id, name):
				print 'WARNING: ' + line
	elif parsed_line.syscall == 'ioctl':
		fd = int(parsed_line.args[0])
		if not hasattr(parsed_line, 'err'):
			if fd not in [0, 1, 2]:
				if fdtracker.is_watched(fd):
					print line 
				name = None
				if fdtracker_unwatched.is_watched(fd):
					name = fdtracker_unwatched.get_name(fd)
				debug_level = 0
				for start in ['/usr/bin', '/dev/snd', '/dev/tty', '/dev/vmnet', '/dev/urandom'] + paceconfig(machine_id).ignore_ioctl:
					if str(name).startswith(start):
						debug_level = 2
				if name == None:
					debug_level = 2
				if paceconfig(machine_id).debug_level >= debug_level:
					print 'WARNING: ' + line + ' name = ' + str(name)
	elif parsed_line.syscall in ['shmget', 'shmat', 'shmdt', 'shmctl']:
		if parsed_line.syscall == 'shmget':
			pass
	elif parsed_line.syscall == 'execve':
		proctracker.record_execve(machine_id)
	elif parsed_line.syscall in ['io_setup', 'aio_read', 'io_getevents', 'io_destroy']:
		if paceconfig(machine_id).debug_level >= 2:
			print 'Warning: AIO ' + line
	elif parsed_line.syscall == 'symlink' or parsed_line.syscall == 'symlinkat':
		if parsed_line.syscall == 'symlinkat':
			print parsed_line
			pass
		else:
			if eval(parsed_line.ret) != -1:
				source = proctracker.original_path(eval(parsed_line.args[0]))
				dest = proctracker.original_path(eval(parsed_line.args[1]))
				if is_interesting(machine_id, dest) or is_interesting(machine_id, source):
					print 'WARNING: ' + line
				if is_interesting(machine_id, dest):
					source_is_dir = False
					if source.startswith(paceconfig(machine_id).base_path):
						if os.path.isdir(replayed_path(machine_id, source)):
							source_is_dir = True
					else:
						print 'WARNING: symlink source outside base path. Assuming file link.'
					if source_is_dir == True:
						os.mkdir(replayed_path(machine_id, dest), 0777)
						inode = __replayed_stat(machine_id, dest).st_ino
						__directory_symlinks.append(inode)
						micro_operations.append(Struct(op = 'mkdir', name = dest, mode = '0777', inode = inode, parent = __parent_inode(machine_id, dest)))
					else:
						tmp_fd = os.open(replayed_path(machine_id, dest), os.O_CREAT | os.O_WRONLY, 0666)
						assert tmp_fd > 0
						os.close(tmp_fd)
						inode = __replayed_stat(machine_id, dest).st_ino
						new_op = Struct(op = 'creat', name = dest, mode = 0666, inode = inode, parent = __parent_inode(machine_id, dest))
						micro_operations.append(new_op)
	elif parsed_line.syscall == 'mremap':
		ret_address = safe_string_to_int(parsed_line.ret)
		if ret_address != -1:
			start_addr = safe_string_to_int(parsed_line.args[0])
			end_addr = start_addr + safe_string_to_int(parsed_line.args[1]) - 1
			assert(len(memtracker.resolve_range(start_addr, end_addr)) == 0)
	else:
		if parsed_line.syscall in interesting_net_calls:
			if parsed_line.syscall == 'socket' or parsed_line.syscall == 'socketpair':
				# int socket(int domain, int type, int protocol) is the signature
				domain = parsed_line.args[0]
				flags = parsed_line.args[1].split('|')
				sock_fd = safe_string_to_int(parsed_line.ret)
				protocol_number = 0

				fd_flags = []
				if 'SOCK_CLOEXEC' in flags:
					fd_flags.append('O_CLOEXEC')

				#Do Unix sockets or Kernel user interface device matter?
				if 'PF_LOCAL' in domain or 'PF_NETLINK' in domain:
					socktracker_unwatched.new_sfd_mapping(sock_fd, 'UNWATCHED' +'_'+ str(sock_fd), \
														None, -1, None, -1, attribs = fd_flags)
				else:
					assert parsed_line.args[2] == "IPPROTO_IP" or parsed_line.args[2] == "IPPROTO_TCP" or parsed_line.args[2] == "IPPROTO_UDP"
					
					name = str(machine_id) 			
					if sock_fd >= 0:
						newly_created = True
						if 'SOCK_STREAM' in flags:
							name += "_TCP"
						elif 'SOCK_DGRAM' in flags:
							name += "_UDP"
						else:
							assert False

						#At this point we dont have host and port details
						socktracker.new_sfd_mapping(sock_fd, name +'_'+ str(sock_fd), None, -1, None,\
												 -1, attribs = fd_flags)
						new_op = Struct(op = 'socket', name = name +'_'+ str(sock_fd), family = domain,\
									 type = flags[0], protocol = protocol_number, )
						micro_operations.append(new_op)
			elif parsed_line.syscall == 'connect':
				#int connect(int sockfd, const struct sockaddr *addr,socklen_t addrlen) is the signature
				#sa_family=AF_INET, sin_port=htons(12345), sin_addr=inet_addr("127.0.1.1")
				if hasattr(parsed_line, 'err') and 'ECONNREFUSED' in parsed_line.err:
					return []
				if hasattr(parsed_line, 'err') and 'ENOENT' in parsed_line.err:
					return []
				
				sock_fd = safe_string_to_int(parsed_line.args[0])
	
				if socktracker.is_watched(sock_fd):
					server_port = -1
					server_host = None
					client_host = None
					client_port = -1

					(server_host, server_port) = __socket_parser(machine_id, parsed_line)
					assert server_host is not None
					assert server_port != -1
					server_port = safe_string_to_int(server_port)
					
					client_host = parsed_line.args[-2].replace('\"', '')
					client_port = safe_string_to_int(parsed_line.args[-1])
					
					same_machine_communication = (client_host == server_host)
					ip_addr_not_interesting = (not connection_manager.is_interesting_ip(client_host)) or (not connection_manager.is_interesting_ip(server_host))
					port_not_interesting  = (client_port not in well_known_ports) and (server_port not in well_known_ports)

					if ip_addr_not_interesting or port_not_interesting or same_machine_communication:
						# Both ips involved in a connect should be interesting for it to be tracked.
						# This means that this connect is not interesting and we can move the socket from
						# watched to unwatched instance
						old_socket = socktracker.get_socket_struct(sock_fd)
						socktracker.remove_sfd_mapping(sock_fd)
						socktracker_unwatched.new_sfd_mapping(sock_fd, old_socket.name, \
															old_socket.server_host, old_socket.server_port,
															old_socket.client_host, old_socket.client_port, old_socket.attribs)
					else:
						assert connection_manager.is_interesting_ip(server_host) and connection_manager.is_interesting_ip(client_host)
						assert client_port in well_known_ports or server_port in well_known_ports

						connect_time = parsed_line.time
						assert type(server_port) == int and server_port > 0
						assert type(client_port) == int and client_port > 0
						
						socktracker.set_server_host_and_port(sock_fd, server_host, server_port)
						socktracker.set_client_host_and_port(sock_fd, client_host, client_port)
					
						candidate_client_socket = connection_manager.connected_ends(server_host, server_port, client_host, client_port, connect_time)
						
						if candidate_client_socket is not None:
							assert len(candidate_client_socket) == 1
							if candidate_client_socket[0] is not None:
								assert connection_manager.machine_id_for_address(candidate_client_socket[0][0]) == machine_id
						
						assert 'undefined_host' not in server_host
						new_op = Struct(op = 'connect', name=str(socktracker.get_name(sock_fd)), server_host=str(server_host),\
									 server_port=server_port, client_host=client_host, client_port=client_port)
						micro_operations.append(new_op)
			elif parsed_line.syscall == 'sendto':
				#sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
				sock_fd = safe_string_to_int(parsed_line.args[0])
				if socktracker.is_watched(sock_fd):
					#for now ignore the sockaddr struct. Assume everyone does connect and then send
					send_data_size = safe_string_to_int(parsed_line.ret)
					dump_file = eval(parsed_line.args[-2])
					dump_offset = safe_string_to_int(parsed_line.args[-1])
	
					server_host = socktracker.get_server_host(sock_fd)
					server_port = socktracker.get_server_port(sock_fd)
					client_host = socktracker.get_client_host(sock_fd)
					client_port = socktracker.get_client_port(sock_fd)
	
					assert type(server_port) == int
					assert type(client_port) == int
					
					if not (server_host is not None and server_port != -1):
						print line
					assert server_host is not None and server_port != -1
					assert client_host is not None and client_port != -1
					
					if send_data_size > 0:
						new_op = Struct(op = 'send', name = str(socktracker.get_name(sock_fd)), size = send_data_size,\
									dump_file = dump_file, dump_offset = dump_offset, server_host = server_host,\
									server_port = server_port, client_host = client_host, client_port = client_port,\
									remaining = send_data_size)
						micro_operations.append(new_op)
			elif parsed_line.syscall == 'recvfrom':
				#recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
				sock_fd = safe_string_to_int(parsed_line.args[0])
				if socktracker.is_watched(sock_fd):
					recvd_data_size = safe_string_to_int(parsed_line.ret)
					#for now ignore the sockaddr struct. Assume everyone does connect and then send
					server_host = socktracker.get_server_host(sock_fd)
					server_port = socktracker.get_server_port(sock_fd)
					client_host = socktracker.get_client_host(sock_fd)
					client_port = socktracker.get_client_port(sock_fd)
	
					assert type(server_port) == int
					assert type(client_port) == int
					
					assert server_host is not None and server_port != -1
					assert client_host is not None and client_port != -1
	
					if recvd_data_size > 0:
						new_op = Struct(op = 'recv', name = socktracker.get_name(sock_fd), size = recvd_data_size,\
									server_host = server_host, server_port = server_port, client_host = client_host,\
									client_port = client_port, has_cross_deps = True, remaining = recvd_data_size)
						micro_operations.append(new_op)
			elif parsed_line.syscall == 'recv':
				#ssize_t recv(int sockfd, void *buf, size_t len, int flags);
				sock_fd = safe_string_to_int(parsed_line.args[0])
				if socktracker.is_watched(sock_fd):
					recvd_data_size = safe_string_to_int(parsed_line.ret)
					#for now ignore the sockaddr struct. Assume everyone does connect and then send
					server_host = socktracker.get_server_host(sock_fd)
					server_port = socktracker.get_server_port(sock_fd)
					client_host = socktracker.get_client_host(sock_fd)
					client_port = socktracker.get_client_port(sock_fd)
	
					assert type(server_port) == int
					assert type(client_port) == int				
					assert server_host is not None and server_port != -1
					assert client_host is not None and client_port != -1
	
					if recvd_data_size > 0:
						new_op = Struct(op = 'recv', name = socktracker.get_name(sock_fd), size = recvd_data_size,\
									server_host = server_host, server_port = server_port, client_host = client_host,\
									client_port = client_port, has_cross_deps = True, remaining = recvd_data_size)
						micro_operations.append(new_op)
			elif parsed_line.syscall == 'recvmsg':
				#recvmsg(int sockfd, struct msghdr *msg, int flags);
				sock_fd = safe_string_to_int(parsed_line.args[0])
				if socktracker.is_watched(sock_fd):
					recvd_data_size = safe_string_to_int(parsed_line.ret)
					#for now ignore the sockaddr struct. Assume everyone does connect and then send
					server_host = socktracker.get_server_host(sock_fd)
					server_port = socktracker.get_server_port(sock_fd)
					client_host = socktracker.get_client_host(sock_fd)
					client_port = socktracker.get_client_port(sock_fd)
	
					assert type(server_port) == int
					assert type(client_port) == int				
					assert server_host is not None and server_port != -1
					assert client_host is not None and client_port != -1
	
					if recvd_data_size > 0:
						new_op = Struct(op = 'recv', name = socktracker.get_name(sock_fd), size = recvd_data_size,\
									 server_host = server_host, server_port = server_port, client_host = client_host,\
									 client_port = client_port, has_cross_deps = True, remaining = recvd_data_size)
						micro_operations.append(new_op)
			elif parsed_line.syscall == 'sendfile':
				out_fd = safe_string_to_int(parsed_line.args[0])
				in_fd = safe_string_to_int(parsed_line.args[1])
				
				#It is possible to do sendfile from one file to another but applications 
				#generally use it to copy file to a socket. Assert this is true.
				assert fdtracker.is_watched(in_fd) or fdtracker_unwatched.is_watched(in_fd)
				assert socktracker.is_watched(out_fd)
				
				if socktracker.is_watched(out_fd):
					sock_fd = out_fd
					send_data_size = safe_string_to_int(parsed_line.ret)
					dump_file = eval(parsed_line.args[-2])
					dump_offset = safe_string_to_int(parsed_line.args[-1])
					server_host = socktracker.get_server_host(sock_fd)
					server_port = socktracker.get_server_port(sock_fd)
					client_host = socktracker.get_client_host(sock_fd)
					client_port = socktracker.get_client_port(sock_fd)
					
					assert type(server_port) == int
					assert type(client_port) == int					
					assert server_host is not None and server_port != -1
					assert client_host is not None and client_port != -1

					if send_data_size > 0:
						new_op = Struct(op = 'send', name = str(socktracker.get_name(sock_fd)), size = send_data_size,\
									 dump_file = dump_file, dump_offset = dump_offset, server_host = server_host,\
									 server_port = server_port, client_host = client_host, client_port = client_port,\
									 remaining = send_data_size)
						micro_operations.append(new_op)
			elif parsed_line.syscall == 'sendmsg':
				#sendmsg(int sockfd, const struct msghdr *msg, int flags);
				sock_fd = safe_string_to_int(parsed_line.args[0])
				if socktracker.is_watched(sock_fd):
					#for now ignore the sockaddr struct. Assume everyone does connect and then send
					send_data_size = safe_string_to_int(parsed_line.ret)
					dump_file = eval(parsed_line.args[-2])
					dump_offset = safe_string_to_int(parsed_line.args[-1])
					
					server_host = socktracker.get_server_host(sock_fd)
					server_port = socktracker.get_server_port(sock_fd)
					client_host = socktracker.get_client_host(sock_fd)
					client_port = socktracker.get_client_port(sock_fd)
	
					assert type(server_port) == int
					assert type(client_port) == int					
					assert server_host is not None and server_port != -1
					assert client_host is not None and client_port != -1

					if send_data_size > 0:
						new_op = Struct(op = 'send', name = str(socktracker.get_name(sock_fd)), size = send_data_size,\
									 dump_file = dump_file, dump_offset = dump_offset, server_host = server_host,\
									 server_port = server_port, client_host = client_host, client_port = client_port,\
									 remaining = send_data_size)
						micro_operations.append(new_op)
			elif parsed_line.syscall == 'sendmmsg':
				#sendmsg(int sockfd, const struct msghdr *msg, int flags);
				#sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, unsigned int flags)
				sock_fd = safe_string_to_int(parsed_line.args[0])
				assert not socktracker.is_watched(sock_fd)
			elif parsed_line.syscall == 'send':
				#send(int sockfd, const void *buf, size_t len, int flags);
				sock_fd = safe_string_to_int(parsed_line.args[0])
				if socktracker.is_watched(sock_fd):
					#for now ignore the sockaddr struct. Assume everyone does connect and then send
					send_data_size = safe_string_to_int(parsed_line.ret)
					dump_file = eval(parsed_line.args[-2])
					dump_offset = safe_string_to_int(parsed_line.args[-1])
					
					server_host = socktracker.get_server_host(sock_fd)
					server_port = socktracker.get_server_port(sock_fd)
					client_host = socktracker.get_client_host(sock_fd)
					client_port = socktracker.get_client_port(sock_fd)
	
					assert type(server_port) == int
					assert type(client_port) == int				
					assert server_host is not None and server_port != -1
					assert client_host is not None and client_port != -1
	
					if send_data_size > 0:
						new_op = Struct(op = 'send', name = str(socktracker.get_name(sock_fd)), size = send_data_size,\
									 dump_file = dump_file, dump_offset = dump_offset, server_host = server_host,\
									 server_port = server_port, client_host = client_host, client_port = client_port,\
									 remaining = send_data_size)
						micro_operations.append(new_op)
			elif parsed_line.syscall == 'listen':
				sock_fd = safe_string_to_int(parsed_line.args[0])
				if socktracker.is_watched(sock_fd):
					backlog_count = safe_string_to_int(parsed_line.args[1])
					if socktracker.is_watched(sock_fd):
						new_op = Struct(op = 'listen', name = str(socktracker.get_name(sock_fd)), backlog = backlog_count)
						micro_operations.append(new_op)
			elif parsed_line.syscall == 'bind':
				#int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
				#sa_family=AF_INET, sin_port=htons(12345), sin_addr=inet_addr("127.0.1.1")

				sock_fd = safe_string_to_int(parsed_line.args[0])

				if socktracker.is_watched(sock_fd):
					port = -1
					host = 'undefined_host'

					(host, port) = __socket_parser(machine_id, parsed_line)
					assert host is not None
					assert port != -1

					if connection_manager.is_interesting_ip(host):

						port = safe_string_to_int(port)
						
						# Spurious bind due to LD_PRELOADS for connect
						if port not in well_known_ports:
							return []
						
						assert port > 0
						socktracker.set_server_host_and_port(sock_fd, host, port)
						if 'undefined_host' not in host and port != -1:
							new_op = Struct(op = 'bind', name = str(socktracker.get_name(sock_fd)), host = host, port = port)
							micro_operations.append(new_op)
					else:
						old_socket = socktracker.get_socket_struct(sock_fd)
						socktracker.remove_sfd_mapping(sock_fd)
						socktracker_unwatched.new_sfd_mapping(sock_fd, old_socket.name, \
															old_socket.server_host, old_socket.server_port,
															old_socket.client_host, old_socket.client_port, old_socket.attribs)
			elif parsed_line.syscall == 'accept' or parsed_line.syscall == 'accept4':
				#int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
				#sa_family=AF_INET, sin_port=htons(12345), sin_addr=inet_addr("127.0.1.1")
				if parsed_line.syscall == 'accept4':
					flags = parsed_line.args[3].split('|')
				else:
					flags = []

				if hasattr(parsed_line, 'err') and 'EAGAIN' in parsed_line.err:
					return []
				
				sock_fd = safe_string_to_int(parsed_line.args[0])
				new_sock_fd = safe_string_to_int(parsed_line.ret)
				assert sock_fd > 0
				assert new_sock_fd > 0

				if socktracker.is_watched(sock_fd):
					client_port = -1
					client_host = 'undefined_host'

					(client_host, client_port) = __socket_parser(machine_id, parsed_line)

					assert client_host is not None
					assert client_port != -1
					
					server_host = socktracker.get_server_host(sock_fd)
					server_port = socktracker.get_server_port(sock_fd)
					
					same_machine_communication = server_host == client_host
										
					client_port = safe_string_to_int(client_port)
					accept_time = parsed_line.time
					
					assert type(server_port) == int
					assert type(client_port) == int
					assert type(accept_time) == float
					
					if same_machine_communication:
						socktracker_unwatched.new_sfd_mapping(new_sock_fd, socktracker.get_name(sock_fd) + '_' + str(new_sock_fd),\
												 server_host = server_host, server_port = server_port,\
												 client_host = client_host, client_port = client_port, attribs = flags)
					else:
						socktracker.new_sfd_mapping(new_sock_fd, socktracker.get_name(sock_fd) + '_' + str(new_sock_fd),\
												 server_host = server_host, server_port = server_port,\
												 client_host = client_host, client_port = client_port, attribs = flags)
						connection_manager.connect_server_to_client(server_host, server_port, client_host, client_port, accept_time)

						# We can optionally set the client socket information here for the parent socket but that is not necessary
						# Note : If we parse the accept first, then the subsequent connect would be set with proper socket information
						# But what happens if we parse the connect first and then the accept call? This is taken care of. 

						assert 'undefined_host' not in server_host  and server_port != -1 and new_sock_fd != -1
						assert 'undefined_host' not in client_host  and client_port != -1
						
						new_op = Struct(op = 'accept', name = str(socktracker.get_name(sock_fd)), server_host = server_host,\
									 server_port = server_port, client_host = client_host, client_port = client_port,\
									 has_cross_deps = True)
						micro_operations.append(new_op)
			else:
				print "Unhandled network system call: " + parsed_line.syscall
				raise Exception("Unhandled network system call: " + parsed_line.syscall)
		else:
			if parsed_line.syscall not in innocent_syscalls and parsed_line.syscall not in innocent_net_calls \
			and not parsed_line.syscall.startswith("ignore_"):
				raise Exception("Unhandled system call: " + parsed_line.syscall)
	
	for op in micro_operations:
		op.hidden_tid = syscall_tid
		op.hidden_time = parsed_line.time
		op.hidden_duration = parsed_line.duration
		op.hidden_pid = proctracker.pid
		op.hidden_full_line = copy.deepcopy(line)
		op.hidden_parsed_line = copy.deepcopy(parsed_line)
		op.hidden_stackinfo = copy.deepcopy(stackinfo)
		op.hidden_backtrace = __get_backtrace(stackinfo)
	return micro_operations

def set_machine_address_map(address_map):
	global connection_manager
	connection_manager = ConnectionManager(address_map)
	
def set_known_ports(known_ports):
	global well_known_ports
	assert all(isinstance(item, int) for item in known_ports)
	well_known_ports = known_ports
		
def get_micro_ops(machine_id):
	global connection_manager
	global well_known_ports
	assert well_known_ports is not None
	assert connection_manager is not None
	global innocent_syscalls, symtab, SymbolTableEntry

	files = commands.getoutput("ls " + paceconfig(machine_id).strace_file_prefix + ".* | grep -v byte_dump | grep -v stackinfo | grep -v symtab").split()
	rows = []
	
	mtrace_recorded = []
	assert len(files) > 0

	for trace_file in files:

		f = open(trace_file, 'r')
		array = trace_file.split('.')
		pid = int(array[len(array) - 1])

		if array[-2] == 'mtrace':
			mtrace_recorded.append(pid)

		dump_offset = 0
		m = re.search(r'\.[^.]*$', trace_file)
		dump_file = trace_file[0 : m.start(0)] + '.byte_dump' + trace_file[m.start(0) : ]

		if not paceconfig(machine_id).ignore_stacktrace:
			stackinfo_file = open(trace_file[0 : m.start(0)] + '.stackinfo' + trace_file[m.start(0) : ], 'r')

		last_parsed_line = None
		for line in f:
			parsed_line = parse_line(line)
			if parsed_line:
				# Replace any system calls that have a 32-bit
				# equivalent with the equivalent
				if parsed_line.syscall in equivalent_syscall:
					parsed_line.syscall = equivalent_syscall[parsed_line.syscall]
				# On a write, take care of the offset within the dump file 
				if parsed_line.syscall in ['write', 'writev', 'pwrite', 'pwritev', 'mwrite']:
					if parsed_line.syscall == 'pwrite':
						write_size = safe_string_to_int(parsed_line.args[-2])
					else:
						write_size = safe_string_to_int(parsed_line.args[-1])
					m = re.search(r'\) += [^,]*$', line)
					line = line[ 0 : m.start(0) ] + ', "' + dump_file + '", ' + str(dump_offset) + line[m.start(0) : ]
					dump_offset += write_size
				
				if parsed_line.syscall in ['fallocate']:
					m = re.search(r'\) += [^,]*$', line)
					line = line[ 0 : m.start(0) ] + ', "' + os.path.join(os.path.dirname(trace_file), 'fallocate_byte_dump.' + str(parsed_line.args[3])) + '", ' + str(0) + line[m.start(0) : ]
				
				if parsed_line.syscall in ['connect']:
					if hasattr(parsed_line, 'err') and 'ENOENT' in parsed_line.err:
						pass
					else:
						(server_host, server_port) = __socket_parser(machine_id, parsed_line)
						
						if connection_manager.is_interesting_ip(server_host):
							assert last_parsed_line.syscall == 'bind'
							(client_host, client_port) =  __socket_parser(machine_id, last_parsed_line)
							assert client_host is not None
							assert client_port is not None

							m = re.search(r'\) += [^,]*$', line)
							line = line[ 0 : m.start(0) ] + ', "' + client_host + '", ' + str(client_port) + line[m.start(0) : ]
						
				if parsed_line.syscall in ['send', 'sendto', 'sendmsg', 'sendfile']:
					m = re.search(r'\) += [^,]*$', line)
					line = line[ 0 : m.start(0) ] + ', "' + dump_file + '", ' + str(dump_offset) + line[m.start(0) : ]
					dump_offset += 0 
					
				stacktrace = '[]\n' if paceconfig(machine_id).ignore_stacktrace else stackinfo_file.readline()
				if parsed_line.syscall in innocent_syscalls or parsed_line.syscall.startswith("ignore_"):
					pass
				else:
					rows.append((pid, parsed_line.time, line, stacktrace))
				
				# Note: We do a bind before every connect so that we have control over what ports we use
				# Sometimes inbetween the bind and connect we may see a futex call
				if parsed_line.syscall != 'futex':
					last_parsed_line = parsed_line

	rows = sorted(rows, key = lambda row: row[1])
	os.system("rm -rf " + paceconfig(machine_id).scratchpad_dir)
	os.system("cp -R " + paceconfig(machine_id).initial_snapshot + " " + paceconfig(machine_id).scratchpad_dir)

	path_inode_map = get_path_inode_map(paceconfig(machine_id).scratchpad_dir)

	if not paceconfig(machine_id).ignore_stacktrace:
		symtab = pickle.load(open(paceconfig(machine_id).strace_file_prefix + '.symtab'))

	micro_operations = []

	for row in rows:
		syscall_tid = row[0]	
		line = row[2]
		stackinfo = row[3]
		line = line.strip()
		
		parsed_line = parse_line(line)
		
		try:
			current_micro_operations = __get_micro_op(machine_id, syscall_tid, line, stackinfo, mtrace_recorded)

			if current_micro_operations is not None and len(current_micro_operations) > 0:
				micro_operations += current_micro_operations
		except:
			traceback.print_exc()
			print row
			print '----------------------------------------------------'
			for op in micro_operations:
				print op
			print '----------------------------------------------------'
			print paceconfig(machine_id)
			print '----------------------------------------------------'
			os.system("ls -lR " + paceconfig(machine_id).scratchpad_dir)
			exit()

	return (path_inode_map, micro_operations)