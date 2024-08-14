import angr
import claripy

import cozy
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

        afl_area_addr = sess.malloc(100)

        try:
            afl_area_ptr = proj.find_symbol_addr('__afl_area_ptr')
            sess.store(afl_area_ptr, claripy.BVV(afl_area_addr, 64), endness=proj.arch.memory_endness)
        except RuntimeError:
            pass

        sess.add_constraints(cozy.primitives.sym_ptr_constraints(ctx_ptr, ctx, can_be_null=True))
        return sess.run([ctx_ptr, in_buff, BUFF_SIZE, out_ptr_buff, out_len_ptr])

    return (run, {'in_buff_contents': in_buff_contents, 'ctx_ptr': ctx_ptr})

def base64_decode_ctx():
    BUFF_SIZE = 5
    ctx_ptr = claripy.BVS('ctx_ptr', 64)

    in_buff_contents = []
    for i in range(BUFF_SIZE - 1):
        char_sym = claripy.BVS('in_buff_char_{}'.format(i), 8)
        in_buff_contents.append(char_sym)

    in_len = claripy.BVS('inlen', 64)
    out_len = claripy.BVS('outlen', 64)

    def run(proj: Project):
        proj.add_prototype('base64_decode_ctx', 'int base64_decode_ctx(void *, char *, unsigned long, char *, unsigned long *)')
        sess = proj.session('base64_decode_ctx')

        ctx = sess.malloc(8)

        in_buff = sess.malloc(BUFF_SIZE, name='in')
        out_buff = sess.malloc(BUFF_SIZE, name='out')
        out_len_ptr = sess.malloc(BUFF_SIZE, name='outlen')

        print("malloced addresses: ", hex(ctx), hex(in_buff), hex(out_buff), hex(out_len_ptr))

        sess.store(out_len_ptr, out_len, endness=proj.arch.memory_endness)

        for (i, char_sym) in enumerate(in_buff_contents):
            sess.store(in_buff + i, char_sym, endness=proj.arch.memory_endness)

        try:
            afl_area_ptr = proj.find_symbol_addr('__afl_area_ptr')
            afl_area_addr = sess.malloc(100)
            sess.store(afl_area_ptr, claripy.BVV(afl_area_addr, 64), endness=proj.arch.memory_endness)
        except RuntimeError:
            pass

        sess.add_constraints(cozy.primitives.sym_ptr_constraints(ctx_ptr, ctx, can_be_null=True))
        sess.add_constraints(in_len.SGE(0), out_len.SGE(0))
        sess.add_constraints(in_len.SLE(BUFF_SIZE), out_len.SLE(BUFF_SIZE))

        return sess.run([0, in_buff, in_len, out_buff, out_len_ptr])

    return (run, {'in_buff_contents': in_buff_contents, 'in_len': in_len, 'out_len': out_len})


(base64_decode_ctx_run, base64_decode_ctx_args) = base64_decode_alloc_ctx()

pre_results = base64_decode_ctx_run(proj_prepatch)
post_results = base64_decode_ctx_run(proj_postpatch)

comparison = cozy.analysis.Comparison(pre_results, post_results)

cozy.execution_graph.visualize_comparison(proj_prepatch, proj_postpatch, pre_results, post_results, comparison,
                                          args=base64_decode_ctx_args, num_examples=2, open_browser=True, include_actions=True)

exit(0)

proj_postpatch.add_prototype('__afl_maybe_log', 'unsigned char __afl_maybe_log()')

sess = proj_postpatch.session('__afl_maybe_log')
sess.run([])