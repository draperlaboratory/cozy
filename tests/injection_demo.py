import os
import angr
import cozy
import cozy.concolic
import claripy

full_suite = 'FULL_SUITE' in os.environ

proj_prepatched = cozy.project.Project('test_programs/injection_demo/injectionAttack')
proj_prepatched.add_prototype("main", "int main(int argc, char **argv)")

proj_postpatched_good = cozy.project.Project('test_programs/injection_demo/injectionAttack-goodPatch-patcherex')
proj_postpatched_good.add_prototype("main", "int main(int argc, char **argv)")

if full_suite:
    proj_postpatched_bad = cozy.project.Project('test_programs/injection_demo/injectionAttack-badPatch-patcherex')
    proj_postpatched_bad.add_prototype("main", "int main(int argc, char **argv)")
    # ↑ uses too much memory for CI, so it needs to be gated by FULL_SUITE

INPUT_LEN = 20

command_symbols = [claripy.BVS('command', 8) for _ in range(INPUT_LEN - 1)]
role_symbols = [claripy.BVS('role', 8) for _ in range(INPUT_LEN - 1)]
data_symbols = [claripy.BVS('data', 8) for _ in range(INPUT_LEN - 1)]

symbols = set()
symbols.update(command_symbols)
symbols.update(role_symbols)
symbols.update(data_symbols)

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

class sprintf(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self, dst, format_str):
        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]
        strncpy = angr.SIM_PROCEDURES["libc"]["strncpy"]

        command = self.va_arg("char *")
        role = self.va_arg("char *")
        data = self.va_arg("char *")

        command_len = self.inline_call(strlen, command).ret_expr
        role_len = self.inline_call(strlen, role).ret_expr
        data_len = self.inline_call(strlen, data).ret_expr

        addr = dst

        self.state.mem[addr].char = ord('c')
        addr = addr + 1
        self.state.mem[addr].char = ord(':')
        addr = addr + 1

        self.inline_call(strncpy, addr, command, command_len + 1, src_len=command_len)
        addr = addr + command_len

        self.state.mem[addr].char = ord(';')
        addr = addr + 1
        self.state.mem[addr].char = ord('r')
        addr = addr + 1
        self.state.mem[addr].char = ord(':')
        addr = addr + 1

        self.inline_call(strncpy, addr, role, role_len + 1, src_len=role_len)
        addr = addr + role_len

        self.state.mem[addr].char = ord(';')
        addr = addr + 1
        self.state.mem[addr].char = ord('d')
        addr = addr + 1
        self.state.mem[addr].char = ord(':')
        addr = addr + 1

        self.inline_call(strncpy, addr, data, data_len + 1, src_len=data_len)

        return command_len + role_len + data_len + 8

def setup(proj: cozy.project.Project):
    proj.hook_symbol('sprintf', sprintf, replace=True)
    proj.hook_symbol('strlen', cozy.hooks.strlen.strlen, replace=True)
    proj.hook_symbol('strncmp', cozy.hooks.strncmp.strncmp, replace=True)
    proj.hook_symbol('strtok_r', cozy.hooks.strtok_r.strtok_r, replace=True)

    sess = proj.session("main")

    root_cond = ((role_symbols[0] == ord('r')) &
                 (role_symbols[1] == ord('o')) &
                 (role_symbols[2] == ord('o')) &
                 (role_symbols[3] == ord('t')) &
                 (role_symbols[4] == 0))
    guest_cond = ((role_symbols[0] == ord('g')) &
                  (role_symbols[1] == ord('u')) &
                  (role_symbols[2] == ord('e')) &
                  (role_symbols[3] == ord('s')) &
                  (role_symbols[4] == ord('t')) &
                  (role_symbols[5] == 0))

    sess.add_constraints(root_cond | guest_cond)

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

    endness = sess.proj.arch.memory_endness

    sess.store(str_array, claripy.BVV(0, ptr_size_bits))
    sess.store(str_array + ptr_size_bytes, claripy.BVV(command, ptr_size_bits), endness=endness)
    sess.store(str_array + 2 * ptr_size_bytes, claripy.BVV(role, ptr_size_bits), endness=endness)
    sess.store(str_array + 3 * ptr_size_bytes, claripy.BVV(data, ptr_size_bits), endness=endness)

    argc = 4
    argv = str_array
    args = [argc, argv]

    add_str_constraints(sess)

    def assertion_condition(state):
        # Assert that at this point in the program, the role the user originally inputted must be "root\0"
        return ((role_symbols[0] == ord('r')) &
                (role_symbols[1] == ord('o')) &
                (role_symbols[2] == ord('o')) &
                (role_symbols[3] == ord('t')) &
                (role_symbols[4] == 0))

    directive = cozy.directive.Assert.from_fun_offset(proj, "delete", 0x0, assertion_condition, "Role is root at delete")
    sess.add_directives(directive)

    return (args, sess)

def concrete_post_processor(args):
    def transform_str(characters):
        return [chr(n.concrete_value) if (n.concrete_value >= 32 and n.concrete_value <= 126) else n.concrete_value for n in characters]
    return [transform_str(cs) for cs in args]

(args_prepatched, prepatched_sess) = setup(proj_prepatched)
prepatched_results = prepatched_sess.run(args_prepatched)

(args_postpatched_good, postpatched_sess_good) = setup(proj_postpatched_good)
postpatched_results_good = postpatched_sess_good.run(args_postpatched_good)

comparison_good = cozy.analysis.Comparison(prepatched_results, postpatched_results_good, use_unsat_core=False)
cozy.execution_graph.dump_comparison(proj_prepatched, proj_postpatched_good,
                                     prepatched_results, postpatched_results_good, comparison_good,
                                     'test_programs/injection_demo/injectionAttack',
                                     'test_programs/injection_demo/injectionAttack-goodPatch-patcherex',
                                     output_file="cmp_injection_demo_good.json",
                                     concrete_post_processor=concrete_post_processor,
                                     args=[command_symbols, role_symbols, data_symbols],
                                     num_examples=2)

if full_suite:
    (args_postpatched_bad, postpatched_sess_bad) = setup(proj_postpatched_bad)
    postpatched_results_bad = postpatched_sess_bad.run(args_postpatched_bad)


    comparison_bad = cozy.analysis.Comparison(prepatched_results, postpatched_results_bad, use_unsat_core=False)

    cozy.execution_graph.dump_comparison(proj_prepatched, proj_postpatched_bad,
                                         prepatched_results, postpatched_results_bad,
                                         comparison_bad,
                                         'test_programs/injection_demo/injectionAttack',
                                         'test_programs/injection_demo/injectionAttack-badPatch-patcherex',
                                         output_file="cmp_injection_demo_bad.json",
                                         concrete_post_processor=concrete_post_processor,
                                         args=[command_symbols, role_symbols, data_symbols],
                                         num_examples=2)
