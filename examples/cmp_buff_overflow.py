import claripy
import cozy.analysis as analysis
import cozy.claripy_ext as claripy_ext
from cozy.directive import Assume
from cozy.project import Project
from cozy.constants import *
import cozy.primitives as primitives

arg0 = [5, 4, 3]
arg1 = claripy.BVS('idx_arg', INT_SIZE * 8)

def construct_args(sess):
    # Constrain the first argument to satisfy -10 <= arg1 <= 10
    sess.add_constraints(arg1.SGE(-10))
    sess.add_constraints(arg1.SLE(10))
    return [arg0, arg1]

def run_pre_patched():
    proj = Project('test_programs/buff_overflow/buff_overflow')
    proj.add_prototype('patch_fun', 'int patch_fun(int a[], int i)')

    sess = proj.session('patch_fun')
    args = construct_args(sess)
    return sess.run(args)

# The patched function is the same as the original, except it has an if statement
# to check if the input argument is NULL
def run_post_patched():
    proj = Project('test_programs/buff_overflow/buff_overflow_patched')
    proj.add_prototype('patch_fun', 'int patch_fun(int a[], int i)')

    sess = proj.session('patch_fun')
    args = construct_args(sess)
    #sess.add_directives(Assume.from_fun_offset(proj, "patch_fun", 0x0, lambda st: (st.regs.rsi >= 0) & (st.regs.rsi < 3)))
    return sess.run(args)

print("Running pre-patched.")
pre_patched = run_pre_patched()
print("\nRunning post-patch.")
post_patched = run_post_patched()

def concrete_post_processor(args):
    return (args[0], primitives.from_twos_comp(args[1].concrete_value, 32))

args = (arg0, arg1)
comparison_results = analysis.Comparison(pre_patched, post_patched)
print(comparison_results.report(args, concrete_post_processor=concrete_post_processor))