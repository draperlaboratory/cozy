import angr
import cozy
from cozy.concolic.exploration import ConcolicSim
import logging
import claripy

#logging.getLogger('angr').setLevel('DEBUG')

proj_prepatched = cozy.project.Project('test_programs/injection_demo/injectionAttack')
proj_goodpatch = cozy.project.Project('test_programs/injection_demo/injectionAttack-goodPatch')

proj_prepatched.add_prototype("main", "int main(int argc, char **argv)")
proj_goodpatch.add_prototype("main", "int main(int argc, char **argv)")

INPUT_LEN = 20

command_symbols = [claripy.BVS('command', 8) for _ in range(INPUT_LEN - 1)]
role_symbols = [claripy.BVS('role', 8) for _ in range(INPUT_LEN - 1)]
data_symbols = [claripy.BVS('data', 8) for _ in range(INPUT_LEN - 1)]

command_symbols.append(claripy.BVV(0, 8))
role_symbols.append(claripy.BVV(0, 8))
data_symbols.append(claripy.BVV(0, 8))

# This function ensures that once a null terminating byte is seen, all subsequent bytes in the string
# must be null (\0) bytes
def add_str_constraints(sess: cozy.project.Session):
    def constrain_lst(lst):
        for i in range(len(lst) - 2):
            sym_a = lst[i]
            sym_b = lst[i + 1]
            # Constrain the subsequent byte only if the first byte is \0
            sess.add_constraints(sym_b == claripy.If(sym_a == 0, 0, sym_b))
    constrain_lst(command_symbols)
    constrain_lst(role_symbols)
    constrain_lst(data_symbols)

def setup(sess: cozy.project.Session):
    sess.state.libc.simple_strtok = False
    sess.state.libc.max_symbolic_strstr = 60

    command = sess.malloc(20, name="command")
    role = sess.malloc(20, name="role")
    data = sess.malloc(20, name="data")

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

    add_str_constraints(sess)

    return sess.run(args, cache_intermediate_states=True)

prepatched_sess = proj_prepatched.session("main")
goodpatched_sess = proj_goodpatch.session("main")

proj_prepatched.hook_symbol('strlen', cozy.hooks.strlen.strlen, replace=True)
proj_goodpatch.hook_symbol('strlen', cozy.hooks.strlen.strlen, replace=True)

proj_prepatched.hook_symbol('strncmp', cozy.hooks.strncmp.strncmp, replace=True)
proj_goodpatch.hook_symbol('strncmp', cozy.hooks.strncmp.strncmp, replace=True)

proj_prepatched.hook_symbol('strtok_r', cozy.hooks.strtok_r.strtok_r, replace=True)
proj_goodpatch.hook_symbol('strtok_r', cozy.hooks.strtok_r.strtok_r, replace=True)

prepatched_results = setup(prepatched_sess)
goodpatched_results = setup(goodpatched_sess)

def concrete_arg_mapper(args):
    def transform_str(characters):
        return [chr(n.concrete_value) if (n.concrete_value >= 32 and n.concrete_value <= 126) else n.concrete_value for n in characters]
    return [transform_str(cs) for cs in args]

comparison = cozy.analysis.Comparison(prepatched_results, goodpatched_results, use_unsat_core=False)

cozy.execution_graph.visualize_comparison(proj_prepatched, proj_goodpatch,
                                          prepatched_results, goodpatched_results,
                                          comparison,
                                          concrete_arg_mapper=concrete_arg_mapper,
                                          args=[command_symbols, role_symbols, data_symbols],
                                          num_examples=2, open_browser=True, include_actions=False)
