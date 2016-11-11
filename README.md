REPO NOT COMPLETE: PORTING IN PROGRESS! 

## PACE: Protocol-Aware Correlated Crash Explorer

This is a user documentation of the PACE tool, which can be used to
discover “correlated crash vulnerabilities” in distributed storage systems.  

What are correlated crashes and correlated crash vulnerabilities?
Correlated crashes happen when power outages cause entire data centers to fail or when correlated reboots (due to kernel bugs or upgrades) that take down all data replicas of a storage system almost
simultaneously. Correlated crash vulnerabilities are problems in distributed storage systems such as data loss, data corruption, or unavailability that occur when correlated crashes occur. 

How does PACE work at a very high-level?
PACE first traces the events (like sending a message, receiving a message, writing to local storage etc.,) in a distributed storage system when a workload is run. Then, it processes the collected traces to find the network and file-system operations. Then, it calculates the persistent disk states could be reached if a correlated crash had happened during the execution of the workload. On each such state, PACE asserts conditions such as "did the system corrupt my data?",  "did the system become unavailable?", or "did the system lose my data?". These assertions are codified in a small script called the checker script.   Currently, PACE only aims to work against distributed storage systems that use commodity file systems such as ext4 or btrfs.  

## 1. Getting Started

Requirements on a typical Ubuntu machine:

 1. Python-2.7, as the default version of python invoked via
    /usr/bin/env python.
 2. Standard software build tools, such as gcc and GNU Make.
 3. The libunwind libraries, installable in Ubuntu using apt-get
    install libunwind8-dev.

Prerequisite steps to follow on clean machine

sudo apt-get update
sudo apt-get install build-essential
sudo  apt-get install libunwind8-dev
sudo apt-get install libaio-dev
sudo apt-get -y install python-setuptools
sudo easy_install pip
sudo pip install bitvector
sudo apt-get -y install libjpeg-dev
sudo apt-get -y install python-reportlab
sudo pip install reportlab

You may need to install default jre and jdk (and associated build frameworks such as maven) if you want to test java based systems such as ZooKeeper.

Note: sometimes, alice-strace fails if run as a normal user. if it fails, please run as sudo. Sometimes, the ld_preloads do not work reliably because implicit bind calls done inside them sometime may fail. Retracing and reparsing usually helps. 

PACE was tested on Ubuntu-12.02 and Ubuntu 14.04, and is expected to work on similar (i.e., Linux-like) operating systems. 

The following are the steps to install PACE:

 1. Clone the latest repository. This should produce a directory named PACE.
 2. In PACE directory, you should find pace-record.py (that records the events) and pace-check.py (that checks for vulnerabilities). These are the entry points to test any system. If needed, one can add the path to these files in .bashrc or these scripts can be invoked using path. 
 4. Install the alice-strace tracing framework by moving into the PACE/alice-strace directory, and running ./configure; make; make install; once this is done, just type alice-strace and see if it prints the help. 

## 2. An Example

This section describes how to use PACE to find correlated crash vulnerabilities in ZooKeeper. 

#### ZooKeeper

###### Initialize the cluster to a known state 

Initialization (zk_init), workload (zk_workload), and checker (zk_checker) for ZooKeeper can be found in  PACE/example/zk. 
There are also some configuration files (zoo2.cfg, zoo3.cfg, and zoo4.cfg) used to configure different ZooKeeper nodes. 
 
Side note: We will associate the number '2' for the first storage server, '3' for the second, and '4' for the third server. We use '1' to denote the client. So, zoo2.cfg is the configuration for the first server. 

Here is the content of the config file:

tickTime=2000
dataDir=/mnt/data1/PACE/example/zk/workload_dir2
clientPort=2182
initLimit=5
syncLimit=2
server.1=127.0.0.2:2888:3888
server.2=127.0.0.3:2889:3889
server.3=127.0.0.4:2890:3890

As you can see, the first server is configured with some IPs, also informed about the other servers in the cluster. Importantly, the server is configured to use a directory (some arbitrary location on your local file system) to store all its data. Similarly, other servers are also configured use a directory for their storage. Individual servers should store their data to different directories.  

Next, let us initialize ZooKeeper to store some data. The zk_init.sh file does this. The script starts the cluster with the configuration files that we saw earlier. We are going to test zookeeper-3.4.8. So, install it somewhere and point that directory as ZK_HOME variable in the init script. If everything is configured correctly, you should see something like:

ZooKeeper JMX enabled by default
Using config: /mnt/data1/PACE/example/zk/zoo2.cfg
Starting zookeeper ... STARTED
ZooKeeper JMX enabled by default
Using config: /mnt/data1/PACE/example/zk/zoo3.cfg
Starting zookeeper ... STARTED
ZooKeeper JMX enabled by default
Using config: /mnt/data1/PACE/example/zk/zoo4.cfg
Starting zookeeper ... STARTED

Also, notice that we inserted 8192 'a' s for the ZK node /zk_test. You can think of /zk_test as the key and the 'a's as the value for that key. So if the initialization was successful, you should see this when you run grep -n -i -r aaaaaaaa *:

"Binary file workload_dir2/version-2/log.100000001 matches"
"Binary file workload_dir3/version-2/log.100000001 matches"
"Binary file workload_dir4/version-2/log.100000001 matches"

###### Running a workload and tracing it

Now, we will run the workload to update the 'a's (we inserted as part of the initialization) to 'b's. You can update with arbitrary values. To do this, the workload script first starts the cluster and then invokes a client that does the update.  

Note how the server starting is prepended with the tracing code:

LD_PRELOAD=$ZK_DIR/bcv6.2.so $PACE_DIR/pace-record.py ...

One thing to note:

1. LD_PRELOAD to track info about network calls -- PACE needs to associate sends and recvs across machines to find consistent cuts in the execution. The information spit out by alice-strace is not enough to do this. So, on bind, connect, and accept system calls, PACE intercepts through the LD_PRELOAD binaries to augment those calls with more information. This is essential for correctly associating dependencies. These LD_PRELOAD binaries are already present in the zk directory. These binaries have been tested to work with ZooKeeper. These ld_preload binaries need to be slightly different for different systems (e.g., we need different ld_preloads for systems that use IPv4 and IPv4 for communication) 

NOTE: the workload_dir parameter should be same as the one specified in the configuration file -- this is where a particular server's data is stored.  

After this step, you should see 4 new directories of the form "traces_dir{i}" created. traces_dir1 contains the events that happened on the client, traces_dir2 the first zookeeper server and so on. 

###### Parsing and Checking for correlated crash vulnerabilities

After this step, we need to make sure that the traces we collected do make sense and PACE is able to parse the trace and understand dependencies. To do this, simply do ./run.sh False. False means that just check if we are ready to replay to find vulnerabilities but do not yet start the checking. This is content of the run.sh file.  

$PACE_DIR/pace-check.py --trace_dirs $ZK_DIR/traces_dir2 $ZK_DIR/traces_dir3 $ZK_DIR/traces_dir4 $ZK_DIR/traces_dir1  --threads 1 --sockconf $ZK_DIR/sockconf --checker=$ZK_DIR/zk_checker.py --scratchpad_base /run/shm --explore rsm --replay $1 

It invokes the pace-check tool, trace_dirs tell where are the traces that we want to parse, threads denote the # threads we want to replay with (default is 1), sockconf is a file that informs PACE about the interesting IP addresses and port numbers that we care about in the trace, checker is the script that contains all assertions that we want to make about user data, scratchpad_base is where the correlated crash disk images are going to be saved for checking, the explore parameter tells PACE if the distributed consensus is achieved through a replicated state machine protocol (rsm) or not (non-rsm). This parameter is needed so that PACE can use efficient pruning techniques to find vulnerabilities. Since ZooKeeper uses the ZAB which is a RSM protocol, we just specify --rsm. For non-rsm systems such as Redis, we simply say 'non-rsm' and you need to specify the rules mentioned in the paper (in section 3.3.2). Please see Redis example in the repo.

If you do not want to use PACE's pruning strategies, then you can specify the explore parameter as 'bruteforce'. Warning: if you use bruteforce, your checking can take a very long time. Please read the paper for more details around PACE's pruning techniques. 

If PACE understands all dependencies then it will just spit out all the events that happened in the cluster as part of the workload. Also, you should see the string "Successfully parsed logical operations!" after the events are printed. At this point, we are ready to check for vulnerabilities. 

To check for vulnerabilities, just do ./run.sh True. When you do this, PACE will produce different correlated crash states in the scratchpad_base directory. For each state produced, PACE will invoke the checker script. The checker script will start the cluster and assert expected conditions. 

Note: it is a good idea to specify the scratchpad_base as a directory on a tmpfs file system so that PACE can quickly write the crash states and the checker can quickly read the same. Also, if there are many states, PACE can take many hours to complete the checking.    

If you take a closer look at the zookeeper checker script, you can see that it performs some queries on the state supplied by PACE: it first starts the zookeeper cluster using the correlated crash state produced by PACE, then it invokes a client to perform checking on the data updated by the workload, finally it dumps debug information into a file called "checkresult" in the crash state directory. You can post process all the checkresult files (a simple grep after you see the contents of the checkresult file) to see if there are vulnerabilities. In the near future, we will make these simple result processing scripts also public.   

Aside: PACE's code intentionally asserts conditions profusely. So, PACE will never report false vulnerabilities silently (though it may miss to find vulnerabilities by design). PACE will just assert and stop if anything seems wrong in the trace or anywhere in this entire pipeline.   

## 3. Testing new systems

To test a new system, you can simply follow the same pattern as ZooKeeper (init, workload, checker). More on rsm and non-rsm -- non-rsm rules. 

## 4. Caveats and limitations

PACE is not complete – it can miss vulnerabilities. Specifically, PACE exercises only one and the same reordering
at a time across the set of nodes. This is a limitation in implementation, not a fundamental one. See paper for details. Also, PACE does not focus on finding bugs in agreement protocols. It is interested in studying how distributed update/crash recovery protocols interact with local file system crash behaviors.

As mentioned earlier, PACE depends on LD_PRELOAD working reliably to find dependencies across nodes. Thus, PACE won't work if your binaries are statically linked. In our experience, it is easy to recompile the binaries of most distributed systems to be dynamically linked (by default most are dynamically linked).

We performed all our tests that emulate 3-server cluster and one client. PACE's code was tested only for this configuration. In theory, there should be no problem if you want to test a 5-machine cluster, but we have not done that so far. If you run into bugs, please let us know and we will fix it. 

## 5. Credits, Acknowledgements, and Contact Information

Ramnatthan Alagappan, Aishwarya Ganesan, and Thanumalayan Sankaranarayana Pillai were involved in design of PACE. PACE is inspired from ALICE that finds single-machine crash vulnerabilities (initially designed and implemented by Thanumalayan Sankaranarayana Pillai). Many parts of the code were directly forked off from ALICE and modified. Aishwarya Ganesan tested the tool extensively by applying it to multiple systems. Yuvraj Patel also tested the tool by applying it to elasticsearch.

Ramnatthan Alagappan(ra@cs.wisc.edu) is the primary author of the tool, and is the best contact for bug reports, feature requests, or other clarifications. The PACE tool is a by-product of a Crash Vulnerabilities research project (http://research.cs.wisc.edu/adsl/Publications/ram-osdi16.html) at the University of Wisconsin-Madison, and due credit must be given to everyone who
was involved in or contributed to the project. Please <a href="http://research.cs.wisc.edu/adsl/Publications/pace-osdi16.bib">cite this paper</a>, if you use this work/tool.  

The alice-strace tracing tool is a direct fork off from ALICE project. alice-strace framework is a slight customization of the strace tool (http://sourceforge.net/projects/strace/), along with some code adapted from strace-plus (https://code.google.com/p/strace-plus/). Credits must be given to the authors and contributors of strace and strace-plus.