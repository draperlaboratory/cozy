import archinfo

import cozy.analysis as analysis
import cozy.claripy_ext as claripy_ext
import cozy.execution_graph as execution_graph
from cozy.directive import ErrorDirective
from cozy.concolic.heuristics import CyclomaticComplexityTermination, BBTransitionCandidate
from cozy.concolic.session import JointConcolicSession
from cozy.project import Project
from cozy.session import Session
from cozy.constants import *
import cozy.primitives as primitives
import angr, claripy
from angr.storage.memory_mixins.address_concretization_mixin import MultiwriteAnnotation
import cozy.types

MAX_NUM_ROWS = 3
MAX_NUM_VALS = 5

proj_orig = Project('test_programs/weather_demo/v5/build/weather-orig')
proj_patched_1 = Project('test_programs/weather_demo/v5/build/weather-patched-1')
proj_patched_2 = Project('test_programs/weather_demo/v5/build/weather-patched-2')

def add_prototype(proj):
    proj.add_prototype('process_sensor_data', 'int process_sensor_data()')

add_prototype(proj_orig)
add_prototype(proj_patched_1)
add_prototype(proj_patched_2)

sensor_row_struct = cozy.types.register_type('struct SensorRow {int *vals; int num_vals; struct SensorRow *next; }', proj_orig.arch)
cozy.types.register_types('typedef struct SensorRow *SensorRowPtr;')

latest_data = primitives.sym_ptr(archinfo.ArchAMD64, 'latest_data_init').annotate(MultiwriteAnnotation())
vals = [[claripy.BVS("val_{}_{}".format(i, j), INT_SIZE * 8) for j in range(MAX_NUM_VALS)] for i in range(MAX_NUM_ROWS)]
num_vals = [claripy.BVS("num_vals_{}".format(i), INT_SIZE * 8) for i in range(MAX_NUM_ROWS)]
next_args = [primitives.sym_ptr(archinfo.ArchAMD64, 'next_ptr').annotate(MultiwriteAnnotation()) for i in range(MAX_NUM_ROWS)]

symbols: set[claripy.BVS] = set()
symbols.add(latest_data)
for vals_lst in vals:
    symbols.update(vals_lst)
symbols.update(num_vals)
symbols.update(next_args)

args = ({"latest_data_init": latest_data}, list(zip(vals, num_vals, next_args)))

if input("Would you like to constrain the temperatures to be in the range [-459, 1000)? (y/n)") == "y":
    range_constraint = claripy.And(*[(x.SGE(-459) & x.SLT(1000)) for lst in vals for x in lst])
else:
    range_constraint = True

def initialize_state(sess):
    endness = sess.proj.angr_proj.arch.memory_endness
    # Allocate all the rows
    row_addrs = [sess.malloc(sensor_row_struct.size) for i in range(MAX_NUM_ROWS)]
    # Allocate the value array for each row
    val_addrs = [sess.malloc(INT_SIZE * MAX_NUM_VALS) for i in range(MAX_NUM_ROWS)]
    # For each row
    for (i, (rowaddr, vaddr, vals_row, nvals, nxt)) in enumerate(zip(row_addrs, val_addrs, vals, num_vals, next_args)):
        # Set up the vals pointer
        sess.mem[rowaddr].struct.SensorRow.vals = vaddr
        # Set num_vals to a symbolic value
        sess.mem[rowaddr].struct.SensorRow.num_vals = nvals
        # Constrain num_vals
        sess.add_constraints(0 <= nvals, nvals <= MAX_NUM_VALS)
        # Store symbolic integers in the value array
        for (j, v) in enumerate(vals_row):
            # For some reason angr doesn't seem to like setting values inside arrays
            # use the mem interface, so load manually here
            sess.memory.store(vaddr + j * INT_SIZE, v, endness=endness)
        # Set up the next pointer
        sess.mem[rowaddr].struct.SensorRow.next = nxt
        if (i + 1) < len(row_addrs):
            # If this is not the last row, constrain the next pointer to be null or the next entry
            sess.add_constraints(primitives.sym_ptr_constraints(nxt, row_addrs[i + 1], can_be_null=True))
        else:
            # If this is the last row, constrain the next pointer to be null
            sess.add_constraints(nxt == NULL_PTR)
    # Set up the latest_data global variable
    latest_data_addr = sess.proj.find_symbol_addr("latest_data")
    sess.mem[latest_data_addr].SensorRowPtr = latest_data
    # Constrain latest_data to be either null or point to the first entry
    sess.add_constraints(primitives.sym_ptr_constraints(latest_data, row_addrs[0], can_be_null=True))
    # Add the constraints for the temperature range
    sess.add_constraints(range_constraint)

def add_error_directive(sess: Session):
    # angr will not move abort() calls into the errored list, so we need to
    # set things up to do that in the framework code instead.
    sess.add_directives(ErrorDirective.from_fun_offset(sess.proj, "abort", 0x0))

def run_orig_and_1():
    sess_orig = proj_orig.session('process_sensor_data')
    add_error_directive(sess_orig)
    initialize_state(sess_orig)

    sess_1 = proj_patched_1.session('process_sensor_data')
    add_error_directive(sess_1)
    initialize_state(sess_1)

    joint_sess = JointConcolicSession(sess_orig, sess_1,
                                      candidate_heuristic_left=BBTransitionCandidate(),
                                      candidate_heuristic_right=BBTransitionCandidate(),
                                      termination_heuristic_left=CyclomaticComplexityTermination.from_session(sess_orig),
                                      termination_heuristic_right=CyclomaticComplexityTermination.from_session(sess_1))

    return joint_sess.run([], [], symbols)

def concrete_post_processor(concrete_args):
    (latest_data_init, rows) = concrete_args
    out_rows = []
    row_ptr = latest_data_init["latest_data_init"].concrete_value
    for (vals, num_vals, next_row) in rows:
        if row_ptr == NULL_PTR:
            break
        vals = vals[:num_vals.concrete_value]
        out_rows.append({
            'vals': [primitives.from_twos_comp(v.concrete_value, 32) for v in vals],
            'num_vals': num_vals.concrete_value,
            'next': hex(next_row.concrete_value)
        })
        row_ptr = next_row.concrete_value
    out_latest_data_init = {"latest_data_init": hex(latest_data_init["latest_data_init"].concrete_value)}
    return (out_latest_data_init, out_rows)

(pre_patched, post_patched) = run_orig_and_1()
comparison_results = analysis.Comparison(pre_patched, post_patched)

execution_graph.visualize_comparison(proj_orig, proj_patched_1,
                                     pre_patched, post_patched,
                                     comparison_results,
                                     concrete_post_processor=concrete_post_processor, args=args,
                                     num_examples=2, open_browser=True)
