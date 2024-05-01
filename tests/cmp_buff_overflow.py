import claripy
import cozy.analysis as analysis
import cozy.claripy_ext as claripy_ext
from cozy.directive import Assume
from cozy.project import Project
from cozy.constants import *
import cozy.primitives as primitives
import cozy.execution_graph as execution_graph

arg0 = [5, 4, 3]
arg1 = claripy.BVS('idx_arg', INT_SIZE * 8)

def construct_args(sess):
    # Constrain the first argument to satisfy -10 <= arg1 <= 10
    sess.add_constraints(arg1.SGE(-10))
    sess.add_constraints(arg1.SLE(10))
    return [arg0, arg1]

proj_pre = Project('test_programs/buff_overflow/buff_overflow')
# The patched function is the same as the original, except it has an if statement
# to check if the input argument is NULL
proj_post = Project('test_programs/buff_overflow/buff_overflow_patched')

proj_pre.add_prototype('patch_fun', 'int patch_fun(int a[], int i)')
proj_post.add_prototype('patch_fun', 'int patch_fun(int a[], int i)')

sess_pre = proj_pre.session('patch_fun')
sess_post = proj_post.session('patch_fun')

rslt_pre = sess_pre.run(construct_args(sess_pre))
rslt_post = sess_post.run(construct_args(sess_post))

def concrete_post_processor(args):
    return (args[0], primitives.from_twos_comp(args[1].concrete_value, 32))

args = (arg0, arg1)

comparison = analysis.Comparison(rslt_pre, rslt_post)

execution_graph.dump_comparison(proj_pre, proj_post, rslt_pre, rslt_post, comparison, output_file="cmp_buff_overflow.json", args=args, num_examples=2, include_actions=True)
