import angr
import claripy

import cozy
from cozy.analysis import Comparison
from cozy.project import Project

proj_prepatch = Project('test_programs/paper_eval/retrowrite/base64-gcc')
proj_postpatch = Project('test_programs/paper_eval/retrowrite/base64-retrowrite')

class lava_set(angr.SimProcedure):
    def run(self, bug_num, val):
        pass

class lava_get(angr.SimProcedure):
    def run(self, bug_num):
        return 0x0

class __afl_maybe_log(angr.SimProcedure):
    def run(self):
        return 0x0

def afl_hook(proj: Project):
    proj.hook_symbol('lava_set', lava_set)
    proj.hook_symbol('lava_get', lava_get)
    proj.hook_symbol('__afl_maybe_log', __afl_maybe_log)

afl_hook(proj_prepatch)
afl_hook(proj_postpatch)

###########
# base64_
###########

def base64_decode_alloc_ctx():
    BUFF_SIZE = 4
    ctx_ptr = claripy.BVS('ctx_ptr', 64)

    in_buff_contents = []
    for i in range(BUFF_SIZE):
        char_sym = claripy.BVS('in_buff_char_{}'.format(i), 8)
        in_buff_contents.append(char_sym)

    def run(proj: Project):
        proj.add_prototype('base64_decode_alloc_ctx', 'int base64_decode_ctx(void *, char *, unsigned long, char *, unsigned long *)')

        sess = proj.session('base64_decode_alloc_ctx')

        ctx = sess.malloc(8)

        in_buff = sess.malloc(BUFF_SIZE, name='in')
        out_ptr_buff = sess.malloc(8, name='out')
        out_len_ptr = sess.malloc(8, name='outlen')

        for (i, char_sym) in enumerate(in_buff_contents):
            sess.store(in_buff + i, char_sym, endness=proj.arch.memory_endness)

        sess.add_constraints(cozy.primitives.sym_ptr_constraints(ctx_ptr, ctx, can_be_null=True))
        return sess.run([ctx_ptr, in_buff, BUFF_SIZE, out_ptr_buff, out_len_ptr])

    return (run, {'in_buff_contents': in_buff_contents, 'ctx_ptr': ctx_ptr})

def base64_decode_ctx():
    IN_LEN = 4
    OUT_LEN = (IN_LEN // 4) * 3 + 3
    ctx_ptr = claripy.BVS('ctx_ptr', 64)

    in_buff_contents = []
    for i in range(IN_LEN):
        char_sym = claripy.BVS('in_buff_char_{}'.format(i), 8)
        in_buff_contents.append(char_sym)

    def run(proj: Project):
        proj.add_prototype('base64_decode_ctx', 'int base64_decode_ctx(void *, char *, unsigned long, char *, unsigned long *)')
        sess = proj.session('base64_decode_ctx')

        ctx = sess.malloc(8)

        in_buff = sess.malloc(IN_LEN, name='in')
        for (i, char_sym) in enumerate(in_buff_contents):
            sess.store(in_buff + i, char_sym, endness=proj.arch.memory_endness)

        out_buff = sess.malloc(OUT_LEN, name='out')

        out_len_ptr = sess.malloc(8, name='outlenptr')
        sess.store(out_len_ptr, claripy.BVV(OUT_LEN, 64), endness=proj.arch.memory_endness)

        sess.add_constraints(cozy.primitives.sym_ptr_constraints(ctx_ptr, ctx, can_be_null=True))
        return sess.run([ctx_ptr, in_buff, IN_LEN, out_buff, out_len_ptr])

    return (run, {'in_buff_contents': in_buff_contents, 'ctx_ptr': ctx_ptr})

def base64_decode_ctx_init():
    ctx_contents = claripy.BVS('ctx_contents', 64)

    def run(proj: Project):
        proj.add_prototype('base64_decode_ctx_init', 'void base64_decode_ctx_init(void *)')
        sess = proj.session('base64_decode_ctx_init')
        ctx = sess.malloc(8)

        sess.store(ctx, ctx_contents, endness=proj.arch.memory_endness)

        return sess.run([ctx])

    return (run, {'ctx_contents': ctx_contents})

def base64_encode_alloc():
    in_len = claripy.BVS('in_len', 64)
    MAX_IN_LEN = 16

    in_buff_contents = []
    for i in range(MAX_IN_LEN):
        char_sym = claripy.BVS('in_buff_char_{}'.format(i), 8)
        in_buff_contents.append(char_sym)

    def run(proj: Project):
        proj.add_prototype('base64_encode_alloc', 'unsigned long base64_encode_alloc(char *in, unsigned long, char **)')
        sess = proj.session('base64_encode_alloc')

        in_buff = sess.malloc(MAX_IN_LEN, name='in')
        sess.add_constraints(in_len.SGE(0), in_len.SLE(MAX_IN_LEN))
        for (i, char_sym) in enumerate(in_buff_contents):
            sess.store(in_buff + i, char_sym, endness=proj.arch.memory_endness)

        out_ptr = sess.malloc(8)

        return sess.run([in_buff, in_len, out_ptr])

    return (run, {'in_buff_contents': in_buff_contents, 'in_len': in_len})

def base64_encode():
    in_len = claripy.BVS('in_len', 64)
    def calc_out_len(in_len):
        return ((in_len + 2) / 3) * 4 + 1
    out_len = calc_out_len(in_len)

    MAX_IN_LEN = 16
    MAX_OUT_LEN = calc_out_len(MAX_IN_LEN)

    in_buff_contents = []
    for i in range(MAX_IN_LEN):
        char_sym = claripy.BVS('in_buff_char_{}'.format(i), 8)
        in_buff_contents.append(char_sym)

    def run(proj: Project):
        proj.add_prototype('base64_encode', 'void base64_encode(char *in, unsigned long, char *, unsigned long)')
        sess = proj.session('base64_encode')

        sess.add_constraints(out_len >= in_len)

        in_buff = sess.malloc(MAX_IN_LEN, name='in')
        sess.add_constraints(in_len.SGE(0), in_len.SLE(MAX_IN_LEN))
        for (i, char_sym) in enumerate(in_buff_contents):
            sess.store(in_buff + i, char_sym, endness=proj.arch.memory_endness)

        out_buff = sess.malloc(MAX_OUT_LEN)

        return sess.run([in_buff, in_len, out_buff, out_len])

    return (run, {'in_buff_contents': in_buff_contents, 'in_len': in_len})

def verify_equivalence(comp: Comparison):
    for pair in comp.pairs.values():
        assert(len(pair.mem_diff) == 0)
        assert(len(pair.reg_diff) == 0)

callee_saved = frozenset(
    [
        'rbx', 'ebx', 'bx', 'bl',
        'rsp', 'esp', 'sp', 'spl',
        'rbp', 'ebp', 'bp', 'bpl',
        'r12', 'r12d', 'r12w', 'r12b',
        'r13', 'r13d', 'r13w', 'r13b',
        'r14', 'r14d', 'r14w', 'r14b',
        'r15', 'r15d', 'r15w', 'r15b'
    ]
)

def apply_callee_saved(comp: Comparison):
    # Ignore all registers that are not callee saved
    for pair in comp.pairs.values():
        to_remove = []
        for reg_name in pair.reg_diff.keys():
            if reg_name not in callee_saved:
                to_remove.append(reg_name)
        for reg_name in to_remove:
            del pair.reg_diff[reg_name]


def run_and_verify(f, visualize=False):
    (run, args) = f()
    pre_results = run(proj_prepatch)
    post_results = run(proj_postpatch)
    comparison = cozy.analysis.Comparison(pre_results, post_results)
    apply_callee_saved(comparison)
    verify_equivalence(comparison)
    if visualize:
        cozy.execution_graph.visualize_comparison(proj_prepatch, proj_postpatch, pre_results, post_results, comparison,
                                                  args=args, num_examples=2, open_browser=True, include_actions=True)

run_and_verify(base64_decode_alloc_ctx)
run_and_verify(base64_decode_ctx)
run_and_verify(base64_decode_ctx_init)
run_and_verify(base64_encode_alloc)
run_and_verify(base64_encode)