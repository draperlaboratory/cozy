import claripy
import cozy.analysis as analysis
import cozy.claripy_ext as claripy_ext
from cozy.project import Project
from cozy.constants import *
import cozy.primitives as primitives
from angr.storage.memory_mixins.address_concretization_mixin import MultiwriteAnnotation

#arg0 = primitives.sym_ptr('arr_arg').annotate(MultiwriteAnnotation())
arg0 = [5, 4, 3]
arg1 = claripy.BVS('idx_arg', INT_SIZE * 8).annotate(MultiwriteAnnotation())
#arg1 = claripy.BVV(0x4, size=32)

def construct_args(sess):
    #arr_addr = sess.malloc(INT_SIZE * 3)
    #sess.add_constraints(primitives.sym_ptr_constraints(arg0, arr_addr, can_be_null=False))

    # Constrain the first argument to satisfy -10 <= arg1 <= 10
    sess.add_constraints(claripy_ext.twos_comp_range_constraint(arg1, -10, 10 + 1))

    return [arg0, arg1]

def run_pre_patched():
    proj = Project('test_programs/buff_overflow/buff_overflow')
    proj.add_prototype('patch_fun', 'int patch_fun(int a[], int i)')

    sess = proj.session('patch_fun')
    args = construct_args(sess)
    return (proj.object_ranges(), sess.run(*args))

# The patched function is the same as the original, except it has an if statement
# to check if the input argument is NULL
def run_post_patched():
    proj = Project('test_programs/buff_overflow/buff_overflow_patched')
    proj.add_prototype('patch_fun', 'int patch_fun(int a[], int i)')

    sess = proj.session('patch_fun')
    args = construct_args(sess)
    #sess.add_directives(Assume(proj, "patch_fun", 0x0, lambda st: (st.regs.rsi >= 0) & (st.regs.rsi < 3)))
    return (proj.object_ranges(), sess.run(*args))

print("Running pre-patched.")
(pre_prog_addrs, pre_patched) = run_pre_patched()
print("\nRunning post-patch.")
(post_prog_addrs, post_patched) = run_post_patched()

# We want our memory diff to ignore the part of memory that contains our program
# We are only interested in the stack, heap, and registers
prog_addrs = pre_prog_addrs + post_prog_addrs

#angr.analyses.congruency_check.CongruencyCheck().compare_states(pre_patched.deadended[0], post_patched.deadended[0])
#angr.analyses.congruency_check.CongruencyCheck().compare_states(pre_patched.deadended[0], post_patched.deadended[1])

def concrete_mapper(args):
    return (args[0], primitives.from_twos_comp(args[1], 32))

args = (arg0, arg1)
comparison_results = analysis.compare_states(pre_patched, post_patched, prog_addrs)
print(comparison_results.report(args, concrete_arg_mapper=concrete_mapper))