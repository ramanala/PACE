#!/usr/bin/env  python

import sys
import os
import redis
import time
import subprocess
from kazoo.client import KazooClient
from kazoo.client import KazooRetry
import logging

logging.basicConfig()
old_value = 'a' * 8192
new_value = 'b' * 5 * 4096

host_list = ['127.0.0.2', '127.0.0.3', '127.0.0.4']
port_list = [2182, 2183, 2184]

pace_home = '/mnt/data1/PACE'
config_info = '''tickTime=2000\ndataDir=%s\nclientPort=%s\ninitLimit=5\nsyncLimit=2\nserver.1=127.0.0.2:2888:3888\nserver.2=127.0.0.3:2889:3889\nserver.3=127.0.0.4:2890:3890'''
ZK_HOME='/mnt/data1/scratch/work/adsl-work/d2s/applications/zookeeper-3.4.8/'

crashed_state_directory = sys.argv[1]
base_path = sys.argv[2]

def invoke_cmd(cmd):
	p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = p.communicate()
	return (out, err)


os.system("pkill -f \'java.*zoo*\'")
os.system("pkill -f \'java.*zoo*\'")
os.system("pkill -f \'java.*zoo*\'")

for host in host_list:
	out, err = invoke_cmd('netstat -pn | grep ' + host)
	lines = out.split('\n')
	for line in lines:
		if len(line) > 0:
			pid_start = pid_end = -1
			pid_end = line.rfind('/')
			if pid_end > -1:
				pid_start = line.rindex(' ', 0, pid_end) + 1

			try:
				proc_id = int(line[pid_start:pid_end])
				os.system('kill -9 ' + str(proc_id))
			except:
				pass

def get_server_dirs():
	assert crashed_state_directory is not None and len(crashed_state_directory) > 0
	parts = crashed_state_directory.split('@')
	return parts[0:3]

server_dirs = get_server_dirs()

server_config0 = (config_info) % (server_dirs[0], port_list[0], )
server_config1 = (config_info) % (server_dirs[1], port_list[1], )
server_config2 = (config_info) % (server_dirs[2], port_list[2], )

config_files = ['/tmp/zoo2.cfg', '/tmp/zoo3.cfg', '/tmp/zoo4.cfg']
with open(config_files[0], 'w') as f:
	f.write(server_config0)

with open(config_files[1], 'w') as f:
	f.write(server_config1)

with open(config_files[2], 'w') as f:
	f.write(server_config2)

node_start0 = os.path.join(ZK_HOME, 'bin/zkServer.sh ') + ('start %s > /dev/null 2>&1 &') % (config_files[0],)
node_start1 = os.path.join(ZK_HOME, 'bin/zkServer.sh ') + ('start %s > /dev/null 2>&1 &') % (config_files[1],)
node_start2 = os.path.join(ZK_HOME, 'bin/zkServer.sh ') + ('start %s > /dev/null 2>&1 &') % (config_files[2],)

def invoke_cmd(cmd):
	p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = p.communicate()
	return (out, err)
		
def data_label(to_check):
	if to_check is not None and len(to_check) > 0:
		to_check = to_check.strip().replace(' ','').replace('\n','').replace('\r','')
		if to_check == old_value:
			return 'old'
		elif to_check == new_value:
			return 'new'
		else:
			return 'corrupt'
	return 'None or Missing'

outfile = os.path.join(base_path, 'checkresult')
os.system("rm -rf " + outfile)
os.system("touch " + outfile)

to_write = ''
client_stdout = ''
client_acked = False

with open(os.path.join(base_path, '3.input_stdout'), 'r') as f:
	client_stdout = f.read()

client_acked = ('Done' in client_stdout)


# chdir here so that zk can create the log here in this directory
os.chdir(server_dirs[0]) 
os.system(node_start0)

time.sleep(1)

os.chdir(server_dirs[1]) 
os.system(node_start1)

os.chdir(server_dirs[2]) 
os.system(node_start2)

time.sleep(1)

server_index = 1
max_retry = 5

check_status_cmd1 = '(echo %s == ; (echo stat | nc %s %s | grep Mode)) >> %s' % (host_list[0], host_list[0], str(port_list[0]), outfile)
check_status_cmd2 = '(echo %s == ; (echo stat | nc %s %s | grep Mode)) >> %s' % (host_list[1], host_list[1], str(port_list[1]), outfile)
check_status_cmd3 = '(echo %s == ; (echo stat | nc %s %s | grep Mode)) >> %s' % (host_list[2], host_list[2], str(port_list[2]), outfile)

invoke_cmd(check_status_cmd1)
invoke_cmd(check_status_cmd2)
invoke_cmd(check_status_cmd3)

for server_index in range(1, 4):
	returned = None
	zk = None
	
	proc_command = 'ps aux | grep zookeeper | grep ' + config_files[server_index-1]
	out,err = invoke_cmd(proc_command)
	processes = out.split('\n')
	processes = [p for p in processes if len(p) > 0]
	should_try_connect = False
	if len(processes) >= 2:
		for process in processes:
			if 'java' in process and config_files[server_index-1] in process:
				should_try_connect = True
				break

	# Note: Kazoo client itself retries when connection fails, so we don't need to do that.
	if should_try_connect:
		connect_string = host_list[server_index-1] + ':' + str(port_list[server_index-1])
		kz_retry = KazooRetry(max_tries=3, delay=0.25, backoff=2)
		zk = KazooClient(hosts=connect_string, connection_retry = kz_retry, command_retry = kz_retry, timeout = 1)
		try:
			zk.start()
			returned, stat = zk.get("/zk_test")
			zk.stop()
		except Exception as e:
			to_write += 'PROBLEMATIC:' + str(e) + '\n'
		finally:
			to_write += ('after startup ' + str(server_index) + ' acked:' + str(client_acked) + ' == ' + str(data_label(returned)) + '\n')
	else:
		to_write += 'PROBLEMATIC: Node did not startup\n'

with open(outfile, 'a') as f:
	f.write(to_write)