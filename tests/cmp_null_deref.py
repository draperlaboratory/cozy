import archinfo
import claripy

import cozy.analysis as analysis
from cozy.project import Project
from cozy.directive import Assume, Assert
from cozy.constants import *
import cozy.primitives as primitives
import cozy.execution_graph as execution_graph
from angr.storage.memory_mixins.address_concretization_mixin import MultiwriteAnnotation

arg0 = primitives.sym_ptr(archinfo.ArchAMD64, 'int_arg')

def construct_args(sess):
    concrete_addr = sess.malloc(INT_SIZE)
    sess.add_constraints(primitives.sym_ptr_constraints(arg0, concrete_addr, can_be_null=True))
    return [arg0]

def run_pre_patched():
    proj = Project('test_programs/null_deref/null_deref')
    proj.add_prototype('my_fun', 'void f(int *a)')

    sess = proj.session('my_fun')

    non_null_input = Assume.from_fun_offset(
            project=proj,
            fun_name="my_fun",
            offset=0x0,
            condition_fun=lambda st: st.regs.rdi != NULL_PTR,
            info_str="Input can never be null"
        )
    # To use the above assume, uncomment the following line
    #sess.add_directives(non_null_input)

    mem_write_okay = Assert.from_fun_offset(
            project=proj,
            # The address of the function where we are inserting the assert
            fun_name="my_fun",
            # The offset in the function in which to insert the assert
            offset=0x10,
            # Given an input state, returns a condition that we are asserting
            # In this case, the program dereferences the address stored in RAX,
            # so we want to make sure that's not NULL
            condition_fun=lambda st: st.regs.rax != NULL_PTR,
            # Human readable information to show the user
            info_str="Dereferencing null pointer"
        )
    #sess.add_directives(mem_write_okay)

    args = construct_args(sess)
    run_results = sess.run(args)
    print(run_results.report(args))
    return (proj, run_results)

# The patched function is the same as the original, except it has an if statement
# to check if the input argument is NULL
def run_post_patched():
    proj = Project('test_programs/null_deref/null_deref_patched')
    proj.add_prototype('my_fun', 'void f(int *a)')

    directives = [
        Assert.from_fun_offset(
            project=proj,
            # The address of the function where we are inserting the assert
            fun_name="my_fun",
            # The offset in the function in which to insert the assert
            offset=0x17,
            # Given an input state, returns a condition that we are asserting
            # In this case, the program dereferences the address stored in RAX,
            # so we want to make sure that's not NULL
            condition_fun=lambda st: st.regs.rax != NULL_PTR,
            # Human readable information to show the user
            info_str="Dereferencing null pointer"
        )
    ]

    sess = proj.session('my_fun')
    sess.add_directives(*directives)
    args = construct_args(sess)
    run_results = sess.run(args)
    print(run_results.report(args))
    return (proj, run_results)

(pre_proj, pre_patched) = run_pre_patched()

(post_proj, post_patched) = run_post_patched()

args = [arg0]
comparison_results = analysis.Comparison(pre_patched, post_patched, simplify=True)

def verification_condition(pair: analysis.CompatiblePair):
    return claripy.If(
        arg0 == 0x0,
        (pair.state_left.state.memory.load(0x0, 4) == 0x2a000000) & (pair.state_right.state.memory.load(0x0, 4) == 0x0),
        pair.state_left.state.memory.load(0x0, 4) == pair.state_right.state.memory.load(0x0, 4)
    )
comparison_results.verify(verification_condition)

execution_graph.dump_comparison(pre_proj, post_proj, pre_patched, post_patched, comparison_results, "null_pre.json", "null_post.json", output_file="cmp_simple_cond.json", args=args, num_examples=2)
