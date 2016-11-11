import argparse
import sys
import os
import BitVector
from collections import defaultdict
import itertools
import pickle
import pprint
from sets import Set

parser = argparse.ArgumentParser()
parser.add_argument('--op_file', dest = 'op_file', type = str, default = False)
parser.add_argument("-b","--brute_force_verify", help="Verify combinations via brute force", 
                    action="store_true")
parser.add_argument("-p","--print_dependencies", help="Print dependencies", 
                    action="store_true")
parser.add_argument("-v","--verbose", help="Print dependency calculations.", 
                    action="store_true")
parser.add_argument("-vv","--very_verbose", help="Print internal re-ordering calculations.", 
                    action="store_true")

if __name__ == '__main__':
    args = parser.parse_args()
else:
    args = parser.parse_args([])

if args.very_verbose:
    args.verbose = True

# The list of syscalls we are interested in.
# Interesting parameters.
# write, sync, truncate
calls_of_interest = ["write", "sync", "delete_dir_entry", "create_dir_entry", "truncate"]
net_interesting = ["socket", "bind", "connect", "accept", "listen", "recv", "send"]
calls_of_interest += net_interesting
# The list of syscalls treated as ordering points.
# Sync parameters.
# Offset, count (bytes)
# fsync: offset = 0, count = full size of file.
ordering_calls = ["sync"]
# Metadata calls.
metadata_calls = ["create_dir_entry", "delete_dir_entry"]

# Set of all current dirty writes for a file.
dirty_write_ops = defaultdict(set) 
dirty_write_ops_inode = defaultdict(set)

# Latest global fsync (on any file).
latest_fsync_on_any_file = None 

# Map inodes to filenames (one inode can map to many names) and filenames to
# inode,
inode_to_filenames = defaultdict(set)
filename_to_inode = {} 

class Operation:

    # All the setup
    def __init__(self, micro_op, micro_op_id):
        global inode_to_filenames
        global filename_to_inode


        self.syscall = micro_op.op 
        self.micro_op = micro_op
        # Set of ops that depend on this op: dropping this op means dropping those ops
        # also.
        
        if micro_op.op in net_interesting:
            self.inode = -1
        else:    
            self.inode = micro_op.inode
            
        self.total_num_combos = 0

        if micro_op.op in metadata_calls:  
            if micro_op.op in ["create_dir_entry", "delete_dir_entry"]:
                self.parent = micro_op.parent
            self.filename = micro_op.entry
            # Set up the maps
            filename_to_inode[self.filename] = self.inode
            inode_to_filenames[self.inode].add(self.filename)
        else:
            # Need to consult the map to get the filename.
            # Note that an inode can be mapped to many names. We just get the
            # first name in the list. It shouldn't matter for most operations.
            for x in inode_to_filenames[self.inode]:
                self.filename = x
                break
        # Set offset and count for certain system calls.
        if micro_op.op in ["write", "sync"]:
            self.offset = micro_op.offset
            self.count  = micro_op.count
        if micro_op.op in ["truncate"]:
            self.final_size = micro_op.final_size

        # The file specific ID for each inode 
        op_index = (self.inode, self.syscall)
        self.micro_op_id = micro_op_id
        # The set of ops that this is dependent on.
        self.deps = Set()
        # Update dirty write collection if required.
        self.update_dirty_write_collection()
        # Finally, calculate dependencies
        self.calculate_dependencies()
        # Clear write dependencies if required.
        self.clear_dirty_write_collection()

    # Check if this operation falls into a sync range.
    def is_included_in_sync_range(self, offset, count):
        start = offset
        end = start + count

        if self.syscall == "write":
            write_start = self.offset
            write_end = self.offset + self.count
            if write_start >= start and write_end <= end:
                return True

        if self.syscall == "truncate":
            if self.final_size >= start and self.final_size <= end:
                return True

        if self.syscall in ["create_dir_entry", "delete_dir_entry"]:
            return True

        return False 

    # This updates the dirty write collection.
    def update_dirty_write_collection(self):
        global dirty_write_ops
        global dirty_write_ops_inode
        if self.syscall in ["write", "truncate"]:
            dirty_write_ops_inode[self.inode].add(self)
        # If this is a create/dir operation, the operation is actually on the
        # parent inode.
        if self.syscall in ["create_dir_entry", "delete_dir_entry"]:
            dirty_write_ops_inode[self.parent].add(self)
        
    # Clears dirty write collection on fsync.
    # TODO: handle file_sync_range correctly. Currently treating as 
    # the same as fdatasync. 
    def clear_dirty_write_collection(self):
        global dirty_write_ops
        global dirty_write_ops_inode
        global latest_fsync_on_any_file
        if self.syscall in ["sync"]: 
            # Remove the dirty writes which will be flushed by this sync.
            set_of_dops_to_remove = set() 
            for dop in dirty_write_ops_inode[self.inode]:
                if dop.is_included_in_sync_range(self.offset, self.count):
                    set_of_dops_to_remove.add(dop)

            for dop in set_of_dops_to_remove:
                dirty_write_ops_inode[self.inode].remove(dop) 

            latest_fsync_on_any_file = self

    # This method calculates the existential dependencies of an operation:
    # basically, we can only include this operation in an combination if one of
    # the conditions for this operation evaluates to true. 
    def calculate_dependencies(self):
    
        # If this is an fsync, then it depends on all the dirty writes to this
        # file previously, which fall within the sync range.
        if self.syscall in ["sync"]:
            for wop in dirty_write_ops_inode[self.inode]:
                if wop.is_included_in_sync_range(self.offset, self.count):
                    self.deps = self.deps | wop.deps
                    self.deps.add(wop)

        # The fsync dependency.
        # Each operation on a file depends on the last fsync to the file. The
        # reasoning is that this operation could not have happened without that
        # fsync happening.
        # CLARIFY: does the op depend on the last fsync *on the same file* or
        # just the last fsync (on any file) in the thread?
        # fsync: offset = 0, count = full size of file.
        if latest_fsync_on_any_file:
            self.deps = self.deps | latest_fsync_on_any_file.deps
            self.deps.add(latest_fsync_on_any_file)

    # Store the notation of dependencies as a bit vector.
    def store_deps_as_bit_vector(self, total_len):            
        self.deps_vector = BitVector.BitVector(size = total_len)
        # Set the relevant bits
        for x in self.deps:
            self.deps_vector[x.micro_op_id] = 1

    # Add a dependecy to the operation.
    def add_dep(self, op):
        self.deps = self.deps | op.deps
        self.deps.add(op)

def test_validity(op_list):
    valid = True
    # Dependence check
    op_set = Set(op_list)
    for op in op_list:
        if not op.deps <= op_set:
            return False
    return True

# Globals for combo generation.
generated_combos = set()
max_combo_limit = None
max_combos_tested = 10000000
num_recursive_calls = 0

def get_micro_ops_set(vijayops_set):
    return [[x.micro_op for x in combo] for combo in vijayops_set]

# Class to contain all the test class suites.
class ALCTestSuite:
    # Load it up with a list of micro ops 
    def __init__(self, micro_op_list):
        global dirty_write_ops, dirty_write_ops_inode
        global latest_fsync_on_any_file, inode_to_filenames, filename_to_inode

        # Reset all the global things
        dirty_write_ops = defaultdict(set) 
        dirty_write_ops_inode = defaultdict(set)
        latest_fsync_on_any_file = None 
        inode_to_filenames = defaultdict(set)
        filename_to_inode = {} 

        self.op_list = [] 
        self.generated_combos = set()
        self.max_combo_limit = None
        self.max_combos_tested = 10000000
        self.num_recursive_calls = 0
        self.total_len = 0
        self.id_to_micro_op_map = {}

        for micro_op in micro_op_list:
            #print(micro_op)
            assert(micro_op.op in calls_of_interest)
            x = Operation(micro_op, len(self.op_list))
            self.id_to_micro_op_map[len(self.op_list)] = x
            self.op_list.append(x)

        self.total_len = len(self.op_list)

        # Store the dependencies as bit vectors.
        for op in self.op_list:
            op.store_deps_as_bit_vector(self.total_len)

    # == External ==
    # Test if this combo is valid. Combo is specified using the id numbers of
    # the operations in the combo.
    # 
    # Input: combo ids (set or list of operation ids)
    # Output: Boolean as to whether this is a valid combo. 
    def test_combo_validity(self, combo):
        combo_to_test = []
        for op_id in combo:
            combo_to_test.append(self.id_to_micro_op_map[op_id])
        validity = test_validity(combo_to_test)
        return validity

    # == External ==
    #
    # Add a list of dependencies to the list already computed.
    # 
    # Input: list of tuples. Each tuple (X, Y) indicates that X should now
    # depend on Y. To include X in a combo, you also need Y. 
    # X and Y are op ids. 
    # Output: None. 
    def add_deps_to_ops(self, dep_list):
        dep_list = sorted(dep_list)
        for dep_tuple in dep_list:
            x_id = dep_tuple[0]
            y_id = dep_tuple[1]
            x_op = self.id_to_micro_op_map[x_id]
            y_op = self.id_to_micro_op_map[y_id]
            x_op.add_dep(y_op)

        # Recompute all the dependencies and bit vectors.
        for op in self.op_list:
            for dep_op in op.deps:
                op.deps = op.deps | dep_op.deps
            op.store_deps_as_bit_vector(self.total_len)