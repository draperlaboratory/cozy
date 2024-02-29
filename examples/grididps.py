import cozy
import claripy
import angr

BUFFER_SIZE = 18

proj_prepatched = cozy.project.Project('test_programs/GridIDPS/build/amp_challenge_arm.ino_unstripped.elf')

buffer_position_sym = claripy.BVS('bufferPosition', 32)
available_sym = claripy.BVS('SerialAvailable', 32)
read_sym = claripy.BVS('ReadSym', 8)
inputBuffer_sym = [claripy.BVS('inputBuffer_sym_{}'.format(i), 8) for i in range(BUFFER_SIZE)]

class usb_serial_available(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self):
        print('doing usb_serial_available')
        return available_sym

class usb_serial_getchar(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self):
        print('doing usb_serial_getchar')
        return read_sym.zero_extend(32 - 8)

class usb_serial_write(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self, str, str_len):
        print('doing usb_serial_write')
        return 0

class println(angr.SimProcedure):
    def run(self, arg):
        print('doing println')
        return 0

def run(proj: cozy.project.Project):
    proj.hook_symbol('usb_serial_available', usb_serial_available)
    proj.hook_symbol('usb_serial_getchar', usb_serial_getchar)
    proj.hook_symbol('usb_serial_write', usb_serial_write)
    proj.hook_symbol('_ZN5Print7printlnEv', println)
    proj.add_prototype('loop', 'void loop()')

    sess = proj.session('loop')

    command_log_addr = sess.malloc(3 * BUFFER_SIZE)
    class process_command(angr.SimProcedure):
        def run(self, cmd_str):
            print("doing process_command")
            # Instead of doing the code to process the string, just store it in the command_log buffer
            strncpy = angr.SIM_PROCEDURES["libc"]["strncpy"]
            self.inline_call(strncpy, command_log_addr, cmd_str, 3 * BUFFER_SIZE)
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
        return cozy.claripy_ext.twos_comp_range_constraint(index, 0, BUFFER_SIZE)
    sess.add_directives(cozy.directive.Assert.from_fun_offset(proj, 'loop', 0x20, index_assertion, "index out of bounds in non-newline character branch"))

    def index_assertion2(state):
        index = state.regs.r3
        return cozy.claripy_ext.twos_comp_range_constraint(index, 0, BUFFER_SIZE)
    sess.add_directives(cozy.directive.Assert.from_fun_offset(proj, 'loop', 0x36, index_assertion2, "index out of bounds in newline character branch"))

    return sess.run(loop_arguments)

results_prepatched = run(proj_prepatched)

comparison_results = cozy.analysis.Comparison(results_prepatched, results_prepatched)

def concrete_arg_mapper(args):
    ret = dict(args)
    ret['bufferPosition'] = cozy.primitives.from_twos_comp(args['bufferPosition'].concrete_value, 32)
    ret['available'] = False if args['available'].concrete_value == 0 else True
    ret['read_sym'] = chr(args['read_sym'].concrete_value)
    return ret

cozy.execution_graph.visualize_comparison(proj_prepatched, proj_prepatched,
                                          results_prepatched, results_prepatched,
                                          comparison_results,
                                          args={"bufferPosition": buffer_position_sym, "inputBuffer": inputBuffer_sym,
                                                'read_sym': read_sym, 'available': available_sym},
                                          num_examples=2, open_browser=True, concrete_arg_mapper=concrete_arg_mapper)