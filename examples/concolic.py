import cozy.concolic
import angr
import archinfo
from angr.storage.memory_mixins.address_concretization_mixin import MultiwriteAnnotation
import claripy

def run_null_deref():
    proj = angr.Project('test_programs/null_deref/null_deref_patched')
    arg0 = cozy.primitives.sym_ptr(archinfo.ArchAMD64, 'int_arg').annotate(MultiwriteAnnotation())
    init_state = proj.factory.call_state(proj.loader.find_symbol('my_fun').rebased_addr, arg0, prototype='void f(int *a)')

    explorer = cozy.concolic.exploration.ConcolicSim({arg0: claripy.BVV(0, 64)})
    simgr = proj.factory.simulation_manager(init_state)
    simgr.use_technique(explorer)
    simgr.explore()
    return simgr

def run_target5():
    proj = angr.Project('test_programs/amp_target5_hackathon/gs_data_processor')

    cozy.types.register_type('struct RoverData_t { int temp; unsigned int cmd; }', proj.arch)
    rover_message_struct = cozy.types.register_type('struct RoverMessage_t { unsigned char header[8]; struct RoverData_t packetData; }', proj.arch)

    temp = claripy.BVS("temp", 32)
    cmd = claripy.BVS("cmd", 32)

    addr = proj.loader.find_symbol('rover_process').rebased_addr
    proto = "int rover_process(struct RoverMessage_t *msg)"

    empty_state = proj.factory.blank_state()

    arg0 = empty_state.heap._malloc(rover_message_struct.size)
    empty_state.mem[arg0].struct.RoverMessage_t.packetData.temp = temp.reversed
    empty_state.mem[arg0].struct.RoverMessage_t.packetData.cmd = cmd.reversed

    init_state = proj.factory.call_state(addr, arg0, prototype=proto, base_state=empty_state)

    explorer = cozy.concolic.exploration.ConcolicSim({cmd: claripy.BVV(0, 32), temp: claripy.BVV(100, 32)})
    simgr = proj.factory.simulation_manager(init_state)
    simgr.use_technique(explorer)
    simgr.explore()

    print(simgr)

    assert(len(simgr.deadended) == 1)

    explorer.set_concrete(simgr, {cmd: claripy.BVV(1073773504, 32), temp: claripy.BVV(100, 32)})
    simgr.explore()

    assert(len(simgr.deadended) == 2)

    print(simgr)

    explorer.set_concrete(simgr, {cmd: claripy.BVV(1073773496, 32), temp: claripy.BVV(100, 32)})
    simgr.explore()

    assert(len(simgr.deadended) == 3)

    print(simgr)

    return simgr

def run_target5_generate():
    proj = angr.Project('test_programs/amp_target5_hackathon/gs_data_processor')

    cozy.types.register_type('struct RoverData_t { int temp; unsigned int cmd; }', proj.arch)
    rover_message_struct = cozy.types.register_type(
        'struct RoverMessage_t { unsigned char header[8]; struct RoverData_t packetData; }', proj.arch)

    temp = claripy.BVS("temp", 32)
    cmd = claripy.BVS("cmd", 32)

    addr = proj.loader.find_symbol('rover_process').rebased_addr
    proto = "int rover_process(struct RoverMessage_t *msg)"

    empty_state = proj.factory.blank_state()

    arg0 = empty_state.heap._malloc(rover_message_struct.size)
    empty_state.mem[arg0].struct.RoverMessage_t.packetData.temp = temp.reversed
    empty_state.mem[arg0].struct.RoverMessage_t.packetData.cmd = cmd.reversed

    init_state = proj.factory.call_state(addr, arg0, prototype=proto, base_state=empty_state)

    explorer = cozy.concolic.exploration.ConcolicSim({cmd, temp})
    simgr = proj.factory.simulation_manager(init_state)
    simgr.use_technique(explorer)

    while len(simgr.active) > 0:
        simgr.explore()
        print(simgr)
        explorer.generate_concrete(simgr, {cmd, temp})

    return simgr

print("Running null deref example...")
run_null_deref()
print("Running target5 example...")
run_target5()
print("Running target5 with autoconcretization...")
run_target5_generate()
print("Done")
