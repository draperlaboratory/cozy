import cozy
import claripy

proj_prepatched = cozy.project.Project('test_programs/amp_target5_hackathon/gs_data_processor')
proj_postpatched = cozy.project.Project('test_programs/amp_target5_hackathon/gs_data_processor_draper_patched')

cozy.types.register_type('struct RoverData_t { int temp; unsigned int cmd; }', proj_prepatched.arch)
rover_message_struct = cozy.types.register_type('struct RoverMessage_t { unsigned char header[8]; struct RoverData_t packetData; }', proj_prepatched.arch)

proj_prepatched.add_prototype("rover_process", "int rover_process(struct RoverMessage_t *msg)")
proj_postpatched.add_prototype("rover_process", "int rover_process(struct RoverMessage_t *msg)")

temp = claripy.BVS("temp", 32)
cmd = claripy.BVS("cmd", 32)

def run(sess: cozy.project.Session):
    arg0 = sess.malloc(rover_message_struct.size)
    sess.mem[arg0].struct.RoverMessage_t.packetData.temp = temp.reversed
    sess.mem[arg0].struct.RoverMessage_t.packetData.cmd = cmd.reversed

    return sess.run([arg0])

prepatched_results = run(proj_prepatched.session("rover_process"))
postpatched_results = run(proj_postpatched.session("rover_process"))

comparison = cozy.analysis.Comparison(prepatched_results, postpatched_results)

cozy.execution_graph.visualize_comparison(proj_prepatched, proj_postpatched,
                                          prepatched_results, postpatched_results,
                                          comparison,
                                          args={"temp": temp, "cmd": cmd},
                                          num_examples=2, open_browser=True, include_actions=True)
