import angr
import cozy

angr.SIM_PROCEDURES["libc"]["strlen"] = cozy.hooks.strlen.strlen
angr.SIM_PROCEDURES["libc"]["strncmp"] = cozy.hooks.strncmp.strncmp

import claripy

from cozy.concolic.heuristics import BBTransitionCandidate, CyclomaticComplexityTermination
from cozy.concolic.session import JointConcolicSession

proj_prepatched = cozy.project.Project('test_programs/injection_demo/injectionAttack')
proj_goodpatch = cozy.project.Project('test_programs/injection_demo/injectionAttack-goodPatch')

proj_prepatched.add_prototype("main", "int main(int argc, char **argv)")
proj_goodpatch.add_prototype("main", "int main(int argc, char **argv)")

INPUT_LEN = 20

symbols = set()

command_symbols = [claripy.BVS('command', 8) for _ in range(INPUT_LEN - 1)]
symbols.update(command_symbols)
command_symbols.append(claripy.BVV(0, 8))
role_symbols = [claripy.BVS('role', 8) for _ in range(INPUT_LEN - 1)]
symbols.update(role_symbols)
role_symbols.append(claripy.BVV(0, 8))
data_symbols = [claripy.BVS('data', 8) for _ in range(INPUT_LEN - 1)]
symbols.update(data_symbols)
data_symbols.append(claripy.BVV(0, 8))

def setup(sess: cozy.project.Session):
    command = sess.malloc(20)
    role = sess.malloc(20)
    data = sess.malloc(20)

    for (i, sym) in enumerate(command_symbols):
        sess.mem[command + i].char = sym

    for (i, sym) in enumerate(role_symbols):
        sess.mem[role + i].char = sym

    for (i, sym) in enumerate(data_symbols):
        sess.mem[data + i].char = sym

    ptr_size_bits = sess.proj.arch.bits
    ptr_size_bytes = ptr_size_bits // 8

    str_array = sess.malloc(4 * ptr_size_bits)

    endness = sess.proj.angr_proj.arch.memory_endness

    sess.store(str_array, claripy.BVV(0, ptr_size_bits))
    sess.store(str_array + ptr_size_bytes, claripy.BVV(command, ptr_size_bits), endness=endness)
    sess.store(str_array + 2 * ptr_size_bytes, claripy.BVV(role, ptr_size_bits), endness=endness)
    sess.store(str_array + 3 * ptr_size_bytes, claripy.BVV(data, ptr_size_bits), endness=endness)

    argc = 4
    argv = str_array
    args = [argc, argv]

    #argv = cozy.primitives.sym_ptr(sess.proj.arch, "argv")

    #sess.add_constraints(cozy.primitives.sym_ptr_constraints(argv, str_array, can_be_null=False))

    #return sess.run([argc, [0, command_symbols, role_symbols, data_symbols]], cache_intermediate_states=True)
    #return sess.run([argc, argv], cache_intermediate_states=True)

    return args

proj_prepatched.angr_proj.hook_symbol('strlen', cozy.hooks.strlen.strlen(project=proj_prepatched.angr_proj), replace=True)
proj_goodpatch.angr_proj.hook_symbol('strlen', cozy.hooks.strlen.strlen(project=proj_goodpatch.angr_proj), replace=True)

proj_prepatched.angr_proj.hook_symbol('strncmp', cozy.hooks.strncmp.strncmp(project=proj_prepatched.angr_proj), replace=True)
proj_goodpatch.angr_proj.hook_symbol('strncmp', cozy.hooks.strncmp.strncmp(project=proj_goodpatch.angr_proj), replace=True)

prepatched_sess = proj_prepatched.session("main")
goodpatched_sess = proj_goodpatch.session("main")

prepatched_args = setup(prepatched_sess)
goodpatched_args = setup(goodpatched_sess)

joint_sess = JointConcolicSession(prepatched_sess, goodpatched_sess,
                                  candidate_heuristic_left=BBTransitionCandidate(),
                                  candidate_heuristic_right=BBTransitionCandidate(),
                                  termination_heuristic_left=CyclomaticComplexityTermination.from_session(prepatched_sess),
                                  termination_heuristic_right=CyclomaticComplexityTermination.from_session(goodpatched_sess))

(prepatched_results, goodpatched_results) = joint_sess.run(prepatched_args, goodpatched_args, symbols, cache_intermediate_states=True)

comparison = cozy.analysis.Comparison(prepatched_results, goodpatched_results)

cozy.execution_graph.visualize_comparison(proj_prepatched, proj_goodpatch,
                                          prepatched_results, goodpatched_results,
                                          comparison,
                                          args=[command_symbols, role_symbols, data_symbols],
                                          num_examples=2, open_browser=True, include_actions=True)
