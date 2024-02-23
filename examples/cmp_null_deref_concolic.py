import archinfo

import cozy.analysis as analysis
from cozy.concolic.heuristics import BBTransitionCandidate, CompleteTermination
from cozy.concolic.session import JointConcolicSession
from cozy.directive import Assume, Assert
from cozy.constants import *
import cozy.primitives as primitives
from angr.storage.memory_mixins.address_concretization_mixin import MultiwriteAnnotation

from cozy.project import Project

arg0 = primitives.sym_ptr(archinfo.ArchAMD64, 'int_arg').annotate(MultiwriteAnnotation())
args = [arg0]

def constrain_args(sess):
    concrete_addr = sess.malloc(INT_SIZE)
    sess.add_constraints(primitives.sym_ptr_constraints(arg0, concrete_addr, can_be_null=True))

def setup_pre_patched():
    proj = Project('test_programs/null_deref/null_deref')
    proj.add_prototype('my_fun', 'void f(int *a)')

    sess = proj.session('my_fun')

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

    constrain_args(sess)
    return sess

# The patched function is the same as the original, except it has an if statement
# to check if the input argument is NULL
def setup_post_patched():
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
    constrain_args(sess)
    return sess

pre_sess = setup_pre_patched()
post_sess = setup_post_patched()

joint_sess = JointConcolicSession(pre_sess, post_sess,
                                  candidate_heuristic_left=BBTransitionCandidate(),
                                  candidate_heuristic_right=BBTransitionCandidate(),
                                  termination_heuristic_left=CompleteTermination(),
                                  termination_heuristic_right=CompleteTermination())
(pre_patched, post_patched) = joint_sess.run(args, args, set(args))

print(pre_patched.report_asserts_failed(args))
print(post_patched.report_asserts_failed(args))

comparison_results = analysis.Comparison(pre_patched, post_patched)

print("\nComparison Results:\n")
print(comparison_results.report(args))
