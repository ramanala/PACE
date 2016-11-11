#!/usr/bin/env  python

import sys
import os
import redis
import time
import subprocess

old_value = 'a' * 8192
new_value = 'b' * 8192

aof_check_command = 'redis-check-aof appendonly.aof'
aof_fix_command = '(yes | redis-check-aof --fix appendonly.aof)'
rdb_check_command = 'redis-check-dump dump.rdb'

pace_home = '/mnt/data1/PACE'

master_start_command = 'redis-server ' + pace_home + '/example/redis/check2.conf --dir %s > /dev/null & '
slave1_start_command = 'redis-server ' + pace_home + '/example/redis/check3.conf --dir %s > /dev/null & '
slave2_start_command = 'redis-server ' + pace_home + '/example/redis/check4.conf --dir %s > /dev/null & '

host_list = ['127.0.0.2', '127.0.0.3', '127.0.0.4']
port_list = [6002, 6003, 6004]

os.system("killall -9 redis-server 2> /dev/null")
os.system("killall -9 redis-check-aof 2> /dev/null")
os.system("killall -9 redis-check-dump 2> /dev/null")

crashed_state_directory = sys.argv[1]
base_path = sys.argv[2]

def invoke_cmd(cmd):
	p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = p.communicate()
	return (out, err)
		
def get_server_dirs():
	assert crashed_state_directory is not None and len(crashed_state_directory) > 0
	parts = crashed_state_directory.split('@')
	return parts[0:3]

def data_label(to_check):
	if to_check is not None and len(to_check) > 0:
		to_check = to_check.strip().replace(' ','').replace('\n','').replace('\r','')
		if to_check == old_value:
			return 'old'
		elif to_check == new_value:
			return 'new'
		else:
			return 'corrupt'
	return None

outfile = os.path.join(base_path, 'checkresult')
os.system("rm -rf " + outfile)
os.system("touch " + outfile)

server_dirs = get_server_dirs()
to_write = ''
server_index = 1
client_stdout = ''
client_acked = False

with open(os.path.join(base_path, '3.input_stdout'), 'r') as f:
	client_stdout = f.read()

client_acked = ('Done' in client_stdout)
	
for server_dir in server_dirs:
	os.chdir(server_dir)
	(out, err) = invoke_cmd(aof_check_command)
	os.system(rdb_check_command + " >> " + outfile)

	if 'AOF is not valid' in out or 'AOF is not valid' in err:
		invoke_cmd(aof_fix_command + " >> " + outfile)

	aof_path = os.path.join(server_dir, 'appendonly.aof')
	content = None
	if os.path.exists(aof_path):
		with open(aof_path, 'r') as f:
			content = f.read()
			from_index = len(content) - 8192 - 2 # Adjust for \r\n used by redis
			to_index = len(content)
			content = content[from_index:to_index]
	else:
		assert content == None
		to_write += 'before startup ' + str(server_index) + ' == ' + str('AOF not found') + '\n'

	if content is not None:
		label = data_label(content)
		to_write += 'before startup ' + str(server_index) + ' == ' + str(label) + '\n'

	if 'rdir-0' in server_dir:
		start_command = master_start_command % (server_dir,) 
	elif 'rdir-1' in server_dir:
		start_command = slave1_start_command % (server_dir,) 
	elif 'rdir-2' in server_dir:
		start_command = slave2_start_command % (server_dir,) 
	else:
		assert False
	os.system(start_command)
	server_index += 1

time.sleep(0.3)
server_index = 1
max_retry = 5

for server_index in range(1, 4):
	backoff = 0.5 
	retry = 0
	returned = None
	while True:
		try:
			r_server = redis.Redis(host_list[server_index-1], port_list[server_index-1])
			returned = r_server.get('key1')
		except:
			if retry < max_retry:				
				retry += 1
				to_write += 'Failed...sleeping for ' + str(backoff) + '\n'
				time.sleep(backoff)
				backoff *= 2
			else:
				to_write += 'Tried ' + str(max_retry) + ' times but still failed.\n'
				break
		else:
			break

	to_write += ('after startup ' + str(server_index) + ' acked:' + str(client_acked) + ' == ' + str(data_label(returned)) + '\n')

with open(outfile, 'a') as f:
	f.write(to_write)

os.system("killall -9 redis-server 2> /dev/null")
os.system("killall -9 redis-check-aof 2> /dev/null")
os.system("killall -9 redis-check-dump 2> /dev/null")