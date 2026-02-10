Launching a Visualization
=================================

In this example we will cover adding user defined types to the angr project as well as
visualizing our results with cozy. We will be using the AMP Hackathon Target 5 binaries,
which can be found in the examples folder in the cozy repository. There is no source
code available for these binaries, so some manual inspection of the assembly in your
preferred reverse engineering tool may be necessary.

The micropatch bug in the Target 5 demo occurs during conversion of the temperature
value. Within the function we want replace the following logic::

    int32_t rover_process(RoverMessage_t* msg){
        // ...
        //convert Kelvin to Farhenheit.
        temp = ( (temp - 273) * 1.8 ) + 32;
        // ...
    }

With this logic::

    int32_t rover_process(RoverMessage_t* msg){
        // ...
        //convert Celsius to Farhenheit.
        temp = ( temp * 1.8 ) + 32;
        // ...
    }

To achieve this patch, we replaced the constant 273 in the original binary with 0.

Let's get started by making two cozy projects, one for each binary::

    proj_prepatched = cozy.project.Project('examples/amp_target5_hackathon/gs_data_processor')
    proj_postpatched = cozy.project.Project('examples/amp_target5_hackathon/gs_data_processor_draper_patched')

==========================
Defining Custom Types
==========================

Our next task will be to define the structs used by this function. The primary inputs
to this function is the temperature field and the cmd field. Let's register these datatypes
with cozy::

    cozy.types.register_type('struct RoverData_t { int temp; unsigned int cmd; }', proj_prepatched.arch)
    rover_message_struct = cozy.types.register_type('struct RoverMessage_t { unsigned char header[8]; struct RoverData_t packetData; }', proj_prepatched.arch)

We are now ready to add the type signature of the method we wish to analyze to the cozy project::

    proj_prepatched.add_prototype("rover_process", "int rover_process(struct RoverMessage_t *msg)")
    proj_postpatched.add_prototype("rover_process", "int rover_process(struct RoverMessage_t *msg)")

==========================
Comparing and Visualizing
==========================

Now let's create two symbolic variables to represent the ``temp`` and ``cmd`` fields in the ``RoverData_t`` struct::

    temp = claripy.BVS("temp", 32)
    cmd = claripy.BVS("cmd", 32)

We now define a run function, which will run a prepatched or postpatched session::

    def run(sess: cozy.project.Session):
        arg0 = sess.malloc(rover_message_struct.size)
        sess.mem[arg0].struct.RoverMessage_t.packetData.temp = temp.reversed
        sess.mem[arg0].struct.RoverMessage_t.packetData.cmd = cmd.reversed

        return sess.run([arg0])

In this case we are mutating the memory by changing the memory of the angr state before
cozy runs. In this case we use angr's API to mutate the temp and cmd fields. Since the
incoming network packet uses network order endianness, we store ``temp.reversed`` and
``cmd.reversed`` to swap the endianness.

Let's use our new run function to run the prepatched and postpatched session::

    prepatched_results = run(proj_prepatched.session("rover_process"))
    postpatched_results = run(proj_postpatched.session("rover_process"))

Now we make the comparison between the two RunResult objects::

    comparison = cozy.analysis.Comparison(prepatched_results, postpatched_results)

After which we can launch the visualization in our web browser. This should automatically
open a browser window which visualizes our results::

    cozy.execution_graph.visualize_comparison(proj_prepatched, proj_postpatched,
                                              prepatched_results, postpatched_results,
                                              comparison,
                                              args={"temp": temp, "cmd": cmd},
                                              num_examples=2, open_browser=True)