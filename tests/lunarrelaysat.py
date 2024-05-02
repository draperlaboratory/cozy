import cozy
import angr
import claripy

proj_prepatched = cozy.project.Project('test_programs/LunarRelaySat/rr.so')
proj_goodpatch = cozy.project.Project('test_programs/LunarRelaySat/rr-good-incorrect-stack.so')

MAX_NUM_PACKETS = 11

packets = [claripy.BVS('packet_body', 300 * 8) for m in range(MAX_NUM_PACKETS)]
recvfrom_ret = [claripy.BVS('recvfrom_ret', 32) for n in range(MAX_NUM_PACKETS)]

GHIDRA_OFFSET = 0x3f0000

ALLOCATE_ADDR = 0x2335C + GHIDRA_OFFSET
class CFE_SB_AllocateMessageBuffer(angr.SimProcedure):
    def run(self, size):
        return self.state.heap._malloc(size)

RECV_FROM_ADDR = 0x232c4 + GHIDRA_OFFSET
class OS_SocketRecvFrom(angr.SimProcedure):
    def run(self, socket_id, buffer, max_size, src_addr, addr_len):
        i = self.state.globals['packet_i']
        self.state.memory.store(buffer, packets[i])
        ret = recvfrom_ret[i]
        self.state.solver.add(ret <= 300)
        self.state.globals['packet_i'] += 1
        return ret

SEND_EVENT_ADDR = 0x2323c + GHIDRA_OFFSET
class CFE_EVS_SendEvent(angr.SimProcedure):
    def run(self):
        return 0

PERF_LOG_ADD_ADDR = 0x23244 + GHIDRA_OFFSET
class CFE_ES_PerfLogAdd(angr.SimProcedure):
    def run(self):
        pass

GET_AP_ID_ADDR = 0x232bc + GHIDRA_OFFSET
class CFE_MSG_GetApId(angr.SimProcedure):
    def run(self):
        return 0

TRANSMIT_BUFFER_ADDR = 0x2322c + GHIDRA_OFFSET
class CFE_SB_TransmitBuffer(angr.SimProcedure):
    def run(self, buffer, is_origination):
        buffer_contents = self.state.memory.load(buffer, 300)
        cozy.side_effect.perform(self.state, 'transmit-buffer', buffer_contents)
        return 0

TO_HEX_ADDR = 0x23304 + GHIDRA_OFFSET
class RR_tohex(angr.SimProcedure):
    def run(self):
        pass

def run(proj: cozy.project.Project):
    proj.add_prototype('RR_ReadTlmInput', 'void RR_ReadTlmInput()')
    proj.add_prototype(ALLOCATE_ADDR, 'void *CFE_SB_AllocateMessageBuffer(int size)')
    proj.add_prototype(RECV_FROM_ADDR, 'unsigned int OS_SocketRecvFrom(int sockfd, void *buf, unsigned int len, void *src_addr, void *addr_len)')

    proj.hook_symbol(ALLOCATE_ADDR, CFE_SB_AllocateMessageBuffer, replace=True)
    proj.hook_symbol(RECV_FROM_ADDR, OS_SocketRecvFrom, replace=True)
    proj.hook_symbol(SEND_EVENT_ADDR, CFE_EVS_SendEvent, replace=True)
    proj.hook_symbol(PERF_LOG_ADD_ADDR, CFE_ES_PerfLogAdd, replace=True)
    proj.hook_symbol(GET_AP_ID_ADDR, CFE_MSG_GetApId, replace=True)
    proj.hook_symbol(TRANSMIT_BUFFER_ADDR, CFE_SB_TransmitBuffer, replace=True)
    proj.hook_symbol(TO_HEX_ADDR, RR_tohex, replace=True)

    sess = proj.session('RR_ReadTlmInput')

    def mutate_init_i(state):
        state.regs.r9 = claripy.BVV(0x9, 32)
    # If you don't want to use a loop_bound, then we can instead directly change the loop counter to a larger number
    # so that it iterates less times.
    #sess.add_directives(cozy.directive.Breakpoint.from_fun_offset(proj, 'RR_ReadTlmInput', 0x2c, mutate_init_i))

    sess.state.globals['packet_i'] = 0

    return sess.run([], loop_bound=3)

results_prepatched = run(proj_prepatched)
results_goodpatch = run(proj_goodpatch)

comparison_results = cozy.analysis.Comparison(results_prepatched, results_goodpatch)

cozy.execution_graph.dump_comparison(proj_prepatched, proj_goodpatch,
                                          results_prepatched, results_goodpatch,
                                          comparison_results,
                                          include_actions=True,
                                          include_side_effects=True,
                                          output_file="cmp_lunar_relay_sat.json",
                                          args={"recvfrom_ret": recvfrom_ret, "packets": packets},
                                          num_examples=2)
