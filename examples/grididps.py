import cozy
import claripy
import angr

from cozy import claripy_ext

BUFFER_SIZE = 18

proj_prepatched = cozy.project.Project('test_programs/GridIDPS/build/amp_challenge_arm.ino_unstripped.elf')
#proj_goodpatch = cozy.project.Project('test_programs/GridIDPS/build/amp_challenge_arm.ino_unstripped-badpatch.elf')
proj_goodpatch = cozy.project.Project('test_programs/GridIDPS/build/amp_challenge_arm.ino_unstripped-goodpatch.elf')

buffer_position_sym = claripy.BVS('bufferPosition', 32)
available_symbols = [claripy.BVS('SerialAvailable', 32) for i in range(7)]
available_symbols.append(claripy.BVV(0, 32))
read_symbols = [claripy.BVS('ReadSym', 8) for j in range(32)]
inputBuffer_sym = [claripy.BVS('inputBuffer_sym_{}'.format(i), 8) for i in range(BUFFER_SIZE)]

class usb_serial_available(angr.SimProcedure):
    def run(self):
        available_sym = available_symbols[self.state.globals['available_i']]
        self.state.globals['available_i'] += 1
        return available_sym

class usb_serial_getchar(angr.SimProcedure):
    def run(self):
        read_sym = read_symbols[self.state.globals['readsym_i']]
        self.state.globals['readsym_i'] += 1
        return read_sym.zero_extend(32 - 8)

class usb_serial_write(angr.SimProcedure):
    def run(self, str, str_len):
        puts = angr.SIM_PROCEDURES["libc"]["puts"]
        self.inline_call(puts, str)
        return 0

class println(angr.SimProcedure):
    def run(self, arg):
        return 0

class setup_hook(angr.SimProcedure):
    def run(self):
        return None

class yield_hook(angr.SimProcedure):
    def run(self):
        return None

def run(proj: cozy.project.Project):
    proj.hook_symbol('usb_serial_available', usb_serial_available)
    proj.hook_symbol('usb_serial_getchar', usb_serial_getchar)
    proj.hook_symbol('usb_serial_write', usb_serial_write)
    proj.hook_symbol('_ZN5Print7printlnEv', println)
    proj.hook_symbol('setup', setup_hook)
    proj.hook_symbol('yield', yield_hook)
    proj.add_prototype('loop', 'void loop()')
    proj.add_prototype('main', 'int main()')

    sess = proj.session('loop')

    sess.add_constraints(buffer_position_sym.SGE(0))
    sess.add_constraints(*[sym.SGE(0) for sym in available_symbols])

    sess.state.globals['available_i'] = 0
    sess.state.globals['readsym_i'] = 0

    class process_command(angr.SimProcedure):
        def run(self, cmd_str):
            strlen = angr.SIM_PROCEDURES["libc"]["strlen"]
            max_len = self.state.solver.max(self.inline_call(strlen, cmd_str).ret_expr)
            cmd = [self.state.memory.load(cmd_str + i, 1) for i in range(max_len)]
            def concrete_post_processor(concrete_cmd):
                return [chr(r.concrete_value) for r in concrete_cmd]
            cozy.side_effect.perform(self.state, "process_command", cmd, concrete_post_processor=concrete_post_processor)
    
    proj.hook_symbol('_Z15process_commandPKc', process_command)

    buffer_position_addr = proj.find_symbol_addr('bufferPosition')
    sess.mem[buffer_position_addr].int = buffer_position_sym

    inputBuffer_addr = proj.find_symbol_addr('inputBuffer')
    for i in range(BUFFER_SIZE):
        sess.mem[inputBuffer_addr + i].char = inputBuffer_sym[i]

    loop_arguments = []

    proj.hook_symbol('strlen', cozy.hooks.strlen.strlen, replace=True)

    def index_assertion(state):
        index = state.regs.r2
        return (index.SGE(0) & index.SLT(BUFFER_SIZE))
    sess.add_directives(cozy.directive.Assert.from_fun_offset(proj, 'loop', 0x20, index_assertion, "index out of bounds in non-newline character branch"))

    def index_assertion2(state):
        index = state.regs.r3
        return (index.SGE(0) & index.SLT(BUFFER_SIZE))
    sess.add_directives(cozy.directive.Assert.from_fun_offset(proj, 'loop', 0x36, index_assertion2, "index out of bounds in newline character branch"))

    return sess.run(loop_arguments)

results_prepatched = run(proj_prepatched)
results_goodpatch = run(proj_goodpatch)

comparison_results = cozy.analysis.Comparison(results_prepatched, results_goodpatch)

def concrete_post_processor(args):
    ret = dict(args)
    ret['bufferPosition'] = cozy.primitives.from_twos_comp(args['bufferPosition'].concrete_value, 32)
    ret['available'] = [av.concrete_value for av in args['available']]
    ret['read_sym'] = [chr(r.concrete_value) for r in args['read_sym']]
    return ret

cozy.execution_graph.visualize_comparison(proj_prepatched, proj_goodpatch,
                                          results_prepatched, results_goodpatch,
                                          comparison_results,
                                          include_actions=True,
                                          include_side_effects=True,
                                          args={"bufferPosition": buffer_position_sym, "inputBuffer": inputBuffer_sym,
                                                'read_sym': read_symbols, 'available': available_symbols},
                                          num_examples=2, open_browser=True, concrete_post_processor=concrete_post_processor)