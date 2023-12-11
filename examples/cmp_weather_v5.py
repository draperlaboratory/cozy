import archinfo

import cozy.analysis as analysis
import cozy.claripy_ext as claripy_ext
import cozy.execution_graph as execution_graph
from cozy.directive import ErrorDirective
from cozy.project import Project, RunResult
from cozy.constants import *
import cozy.primitives as primitives
import angr, claripy
from angr.storage.memory_mixins.address_concretization_mixin import MultiwriteAnnotation

MAX_NUM_ROWS = 3
MAX_NUM_VALS = 5

proj_orig = Project('test_programs/weather_demo/v5/build/weather-orig')
proj_patched_1 = Project('test_programs/weather_demo/v5/build/weather-patched-1')
proj_patched_2 = Project('test_programs/weather_demo/v5/build/weather-patched-2')

sensor_row_struct = angr.types.parse_type('struct SensorRow {int *vals; int num_vals; struct SensorRow *next; }').with_arch(proj_orig.angr_proj.arch)
angr.types.register_types(sensor_row_struct)
sensor_row_ptr = angr.types.parse_types('typedef struct SensorRow *SensorRowPtr;')
angr.types.register_types(sensor_row_ptr)

latest_data = primitives.sym_ptr(archinfo.ArchAMD64, 'latest_data_init').annotate(MultiwriteAnnotation())
vals = [[claripy.BVS("val_{}_{}".format(i, j), INT_SIZE * 8) for j in range(MAX_NUM_VALS)] for i in range(MAX_NUM_ROWS)]
num_vals = [claripy.BVS("num_vals_{}".format(i), INT_SIZE * 8) for i in range(MAX_NUM_ROWS)]
next_args = [primitives.sym_ptr(archinfo.ArchAMD64, 'next_ptr').annotate(MultiwriteAnnotation()) for i in range(MAX_NUM_ROWS)]

if input("Would you like to constrain the temperatures to be in the range [-459, 1000)? (y/n)") == "y":
    range_constraint = claripy.And(*[claripy_ext.twos_comp_range_constraint(x, -459, 1000) for lst in vals for x in lst])
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
        sess.state.mem[rowaddr].struct.SensorRow.vals = vaddr
        # Set num_vals to a symbolic value
        sess.state.mem[rowaddr].struct.SensorRow.num_vals = nvals
        # Constrain num_vals
        sess.add_constraints(0 <= nvals, nvals <= MAX_NUM_VALS)
        # Store symbolic integers in the value array
        for (j, v) in enumerate(vals_row):
            # For some reason angr doesn't seem to like setting values inside arrays
            # use the mem interface, so load manually here
            sess.state.memory.store(vaddr + j * INT_SIZE, v, endness=endness)
        # Set up the next pointer
        sess.state.mem[rowaddr].struct.SensorRow.next = nxt
        if (i + 1) < len(row_addrs):
            # If this is not the last row, constrain the next pointer to be null or the next entry
            sess.add_constraints(primitives.sym_ptr_constraints(nxt, row_addrs[i + 1], can_be_null=True))
        else:
            # If this is the last row, constrain the next pointer to be null
            sess.add_constraints(nxt == NULL_PTR)
    # Set up the latest_data global variable
    latest_data_addr = sess.proj.find_symbol_addr("latest_data")
    sess.state.mem[latest_data_addr].SensorRowPtr = latest_data
    # Constrain latest_data to be either null or point to the first entry
    sess.add_constraints(primitives.sym_ptr_constraints(latest_data, row_addrs[0], can_be_null=True))
    # Add the constraints for the temperature range
    sess.add_constraints(range_constraint)

def run(proj, **kwargs):
    proj.add_prototype('process_sensor_data', 'int process_sensor_data()')
    sess = proj.session('process_sensor_data')
    # angr will not move abort() calls into the errored list, so we need to
    # set things up to do that in the framework code instead.
    sess.add_directives(ErrorDirective.from_fun_offset(proj, "abort", 0x0))
    initialize_state(sess)
    return sess.run(**kwargs)

def run_weather_orig(**kwargs) -> RunResult:
    return run(proj_orig, **kwargs)

def run_weather_patched_1(**kwargs) -> RunResult:
    return run(proj_patched_1, **kwargs)

def run_weather_patched_2(**kwargs) -> RunResult:
    return run(proj_patched_2, **kwargs)

args = ({"latest_data_init": latest_data}, list(zip(vals, num_vals, next_args)))

def concrete_mapper(concrete_args):
    (latest_data_init, rows) = concrete_args
    out_rows = []
    row_ptr = latest_data_init["latest_data_init"]
    for (vals, num_vals, next_row) in rows:
        if row_ptr == NULL_PTR:
            break
        vals = vals[:num_vals]
        out_rows.append({
            'vals': [primitives.from_twos_comp(v, 32) for v in vals],
            'num_vals': num_vals,
            'next': hex(next_row)
        })
        row_ptr = next_row
    return (analysis.hexify(latest_data_init), out_rows)

dump_execution_graphs = input("Would you like to dump the execution graphs of comparing weather-orig and weather-patched-1? (y/n)") == "y"
visualize_execution_graphs = input("Would you like to visualize the comparison of weather-orig and weather-patched-1? (y/n)") == "y"
cache_intermediate_states = dump_execution_graphs or visualize_execution_graphs

print("Running weather-orig")
weather_orig_states = run_weather_orig(cache_intermediate_states=cache_intermediate_states)

if input("Would you like to view error states for weather-orig? (y/n)") == "y":
    print(weather_orig_states.report_errored(args, concrete_arg_mapper=concrete_mapper, num_examples=2))

input("Press enter to run weather-patched-1")

print("\nRunning weather-patched-1")
weather_patched_1_states = run_weather_patched_1(cache_intermediate_states=cache_intermediate_states)
if input("Would you like to view error states for weather-patched-1? (y/n)") == "y":
    print(weather_patched_1_states.report_errored(args, concrete_arg_mapper=concrete_mapper, num_examples=2))

input("Press enter to run weather-patched-2")

print("\nRunning weather-patched-2")
weather_patched_2_states = run_weather_patched_2(cache_intermediate_states=cache_intermediate_states)
if input("Would you like to view error states for weather-patched-2? (y/n)") == "y":
    print(weather_patched_2_states.report_errored(args, concrete_arg_mapper=concrete_mapper, num_examples=2))

if input("Would you like to compare weather-orig and weather-patched-1? (y/n)") == "y":
    print("\n\nCOMPARING WEATHER-ORIG and WEATHER-PATCHED-1")
    comparison_results = analysis.Comparison(weather_orig_states, weather_patched_1_states, compare_memory=True, compare_registers=True)
    print(comparison_results.report(args, concrete_arg_mapper=concrete_mapper))

    if dump_execution_graphs:
        execution_graph.dump_comparison(proj_orig, proj_patched_1,
                                        weather_orig_states, weather_patched_1_states,
                                        comparison_results,
                                        "exec_g_orig.txt", "exec_g_patched_1.txt",
                                        concrete_arg_mapper=concrete_mapper,
                                        args=args, num_examples=2)

    if visualize_execution_graphs:
        execution_graph.visualize_comparison(proj_orig, proj_patched_1,
                                             weather_orig_states, weather_patched_1_states,
                                             comparison_results,
                                             concrete_arg_mapper=concrete_mapper, args=args,
                                             num_examples=2, open_browser=True)

if input("Would you like to compare weather-patched-1 and weather-patched-2? (y/n)") == "y":
    print("\n\nCOMPARING WEATHER-PATCHED-1 and WEATHER-PATCHED-2")
    comparison_results = analysis.Comparison(weather_patched_1_states, weather_patched_2_states)
    print(comparison_results.report(args, concrete_arg_mapper=concrete_mapper))

if input("Would you like to compare weather-orig and weather-patched-2? (y/n)") == "y":
    print("\n\nCOMPARING WEATHER-ORIG and WEATHER-PATCHED-2")
    comparison_results = analysis.Comparison(weather_orig_states, weather_patched_2_states)
    print(comparison_results.report(args, concrete_arg_mapper=concrete_mapper))
