import cozy.analysis as analysis
import cozy.claripy_ext as claripy_ext
from cozy.project import Project
from cozy.constants import *
import cozy.primitives as primitives
from cozy.directive import VirtualPrint
import angr, claripy

def concrete_datafile():
    with open('test_programs/weather_demo/v1/data.txt', 'r') as data_file:
        file_content = data_file.read()
    return angr.SimFile('data.txt', content=file_content)

try:
    num_lines = int(input("How many lines of symbolic temperature readings would you like to use? This should be a small number, perhaps 3 or less to keep the number of states manageable."))
except ValueError:
    print("Error parsing integer. Defaulting to 2 lines.")
    num_lines = 2

symbolic_integers_lst = [
    [claripy.BVS('n0_line_{}'.format(i), INT_SIZE * 8),
     claripy.BVS('n1_line_{}'.format(i), INT_SIZE * 8),
     claripy.BVS('n2_line_{}'.format(i), INT_SIZE * 8),
     claripy.BVS('n3_line_{}'.format(i), INT_SIZE * 8)] for i in range(num_lines)]

if input("Would you like to constrain the temperatures to be in the range [-459, 1000)? (y/n)") == "y":
    range_constraint = claripy.And(*[(x.SGE(-459) & x.SLT(1000)) for lst in symbolic_integers_lst for x in lst])
else:
    range_constraint = True

zero = claripy.BVV(0, INT_SIZE * 8)
four = claripy.BVV(4, INT_SIZE * 8)

class fscanf_wrapper(angr.SimProcedure):
    def __init__(self, endness):
        super().__init__()
        self.endness = endness

    def run(self, file, format_str, n0_ptr, n1_ptr, n2_ptr, n3_ptr):
        if 'loop_itr' not in self.state.globals:
            self.state.globals['loop_itr'] = 0
        loop_itr = self.state.globals['loop_itr']
        if loop_itr < len(symbolic_integers_lst):
            sym_int = symbolic_integers_lst[loop_itr]
            self.state.globals['loop_itr'] += 1

            self.state.memory.store(n0_ptr, sym_int[0], endness=self.endness)
            self.state.memory.store(n1_ptr, sym_int[1], endness=self.endness)
            self.state.memory.store(n2_ptr, sym_int[2], endness=self.endness)
            self.state.memory.store(n3_ptr, sym_int[3], endness=self.endness)

            return four
        else:
            self.state.memory.store(n0_ptr, zero)
            self.state.memory.store(n1_ptr, zero)
            self.state.memory.store(n2_ptr, zero)
            self.state.memory.store(n3_ptr, zero)
            return zero

def run_weather_1():
    proj = Project('test_programs/weather_demo/v1/weather-1')
    proj.add_prototype('main', 'int main()')
    proj.angr_proj.hook_symbol('__isoc99_fscanf', fscanf_wrapper(proj.angr_proj.arch.memory_endness))

    sess = proj.session('main')

    my_print = VirtualPrint.from_fun_offset(
        proj,
        fun_name='scan_temperatures',
        offset=0x4C,
        log_fun=lambda st: st.regs.eax,
        info_str="Computed Average",
        concrete_post_processor=lambda eax_val: primitives.from_twos_comp(eax_val.concrete_value, 32)
    )

    sess.add_directives(my_print)

    sess.add_constraints(range_constraint)
    sess.store_fs('data.txt', concrete_datafile())
    return sess.run([])

def run_weather_2():
    proj = Project('test_programs/weather_demo/v1/weather-2')
    proj.add_prototype('main', 'int main()')
    proj.angr_proj.hook_symbol('__isoc99_fscanf', fscanf_wrapper(proj.angr_proj.arch.memory_endness))
    sess = proj.session('main')

    my_print = VirtualPrint.from_fun_offset(
        proj,
        fun_name='scan_temperatures',
        offset=0x46,
        log_fun=lambda st: st.regs.eax,
        info_str="Computed Average",
        concrete_post_processor=lambda eax_val: primitives.from_twos_comp(eax_val.concrete_value, 32)
    )

    sess.add_directives(my_print)

    sess.add_constraints(range_constraint)
    sess.store_fs('data.txt', concrete_datafile())
    return sess.run([])

def run_weather_3():
    proj = Project('test_programs/weather_demo/v1/weather-3')
    proj.add_prototype('main', 'int main()')
    proj.angr_proj.hook_symbol('__isoc99_fscanf', fscanf_wrapper(proj.angr_proj.arch.memory_endness))
    sess = proj.session('main')

    my_print = VirtualPrint.from_fun_offset(
        proj,
        fun_name='scan_temperatures',
        offset=0x46,
        log_fun=lambda st: st.regs.eax,
        info_str="Computed Average",
        concrete_post_processor=lambda eax_val: primitives.from_twos_comp(eax_val.concrete_value, 32)
    )

    sess.add_directives(my_print)

    sess.add_constraints(range_constraint)
    sess.store_fs('data.txt', concrete_datafile())
    return sess.run([])

args = symbolic_integers_lst
def concrete_post_processor(integers_lst):
    return [[primitives.from_twos_comp(x.concrete_value, 32) for x in integers] for integers in integers_lst]

print("Running weather-1")
weather_1_states = run_weather_1()
if input("Would you like to view error states for weather-1? (y/n)") == "y":
    print(weather_1_states.report_errored(args, concrete_post_processor=concrete_post_processor, num_examples=2))

input("Press enter to run weather-2")

print("\nRunning weather-2")
weather_2_states = run_weather_2()
if input("Would you like to view error states for weather-2? (y/n)") == "y":
    print(weather_2_states.report_errored(args, concrete_post_processor=concrete_post_processor, num_examples=2))

input("Press enter to run weather-3")

print("\nRunning weather-3")
weather_3_states = run_weather_3()
if input("Would you like to view error states for weather-3? (y/n)") == "y":
    print(weather_3_states.report_errored(args, concrete_post_processor=concrete_post_processor, num_examples=2))

mem_reg_diff = False
if input("When comparing programs would you like to use memory and registers to perform the diffing? (y/n)") == "y":
    mem_reg_diff = True

if input("Would you like to compare weather-1 and weather-2? (y/n)") == "y":
    print("\n\nCOMPARING WEATHER-1 and WEATHER-2")
    comparison_results = analysis.Comparison(weather_1_states, weather_2_states, compare_std_out=True, compare_memory=mem_reg_diff, compare_registers=mem_reg_diff)
    print(comparison_results.report(args, concrete_post_processor=concrete_post_processor))

if input("Would you like to compare weather-2 and weather-3? (y/n)") == "y":
    print("\n\nCOMPARING WEATHER-2 and WEATHER-3")
    comparison_results = analysis.Comparison(weather_2_states, weather_3_states, compare_std_out=True, compare_memory=mem_reg_diff, compare_registers=mem_reg_diff)
    print(comparison_results.report(args, concrete_post_processor=concrete_post_processor))

if input("Would you like to compare weather-1 and weather-3? (y/n)") == "y":
    print("\n\nCOMPARING WEATHER-1 and WEATHER-3")
    comparison_results = analysis.Comparison(weather_1_states, weather_3_states, compare_std_out=True, compare_memory=mem_reg_diff, compare_registers=mem_reg_diff)
    print(comparison_results.report(args, concrete_post_processor=concrete_post_processor))