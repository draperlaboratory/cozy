Modeling I/O Side Effects
=========================

Many programs of interest that we wish to simulate produce side effects, which we would like to be available for comparison in our analysis.
To enable this use case, cozy has a subsystem for producing IO side effects. Common examples of IO side effects we have found in example programs
include writing to stdout/stderr, writing to the network, or writing over a serial connection.

Modeling IO side effects is typically straightforward, and can be accomplished by hooking side effect producing functions and instead redirecting
the side effect payload to a list attached to the current state. When a child state is forked from its parent, it obtains a copy of side effects
from its parent. cozy keeps track of IO side effects over different channels (ie, a channel for stdout, network, etc.) and attempts to
intelligently align side effects in the visualization interface.

Note that by default, angr automatically concretizes data written to stdout/stderr. cozy side effects keeps the data symbolic and avoids the concretization.
In this way cozy's side effects interface is superior to the angr default.

==========================
Performing a Side Effect
==========================

The primary function to take a look at is :py:func:`cozy.side_effect.perform`. The first argument is the :py:class:`angr.SimState` that the side effect
will attach to. This argument can be obtained by hooking a side effect function, whose :py:meth:`angr.SimProcedure.run` method takes in a
:py:class:`angr.SimState` object. Alternatively you can set a breakpoint using :py:class:`cozy.directive.Breakpoint` and obtain the :py:class:`angr.SimState`
object in the breakpoint's `breakpoint_fun` callback.

Here is an example of the use of :py:func:`cozy.side_effect.perform` in a custom :py:class:`angr.SimProcedure` hook::

    # Here we are hooking a function called process_command,
    # so we need to make a class that inherits from SimProcedure
    class process_command(angr.SimProcedure):
        def run(self, cmd_str):
            strlen = angr.SIM_PROCEDURES["libc"]["strlen"]
            max_len = self.state.solver.max(self.inline_call(strlen, cmd_str).ret_expr)
            # Here we construct the side effect payload. Here it is a bunch of symbolic data.
            cmd = [self.state.memory.load(cmd_str + i, 1) for i in range(max_len)]
            def concrete_post_processor(concrete_cmd):
                return [chr(r.concrete_value) for r in concrete_cmd]
            cozy.side_effect.perform(self.state, "process_command", cmd, concrete_post_processor=concrete_post_processor)

The second argument is the side effect channel. Different types of side effects should be performed over different channels. For example,
you may have a channel for networked output and a channel for stdout.

The third argument is the side effect body. The body must be a mixture of string-keyed Python dictionaries, Python lists, Python tuples,
claripy concrete values, and claripy symbolic values. This should represent the payload of the side effect.

The fourth argument is an optional post processing function to apply to concretized versions of the side effect's body if post processing is required.
In this example we use the Python `chr` function to convert the integer to Python characters, which will be shown in the visualization
user interface.

The fifth argument is an optional label used to aid alignment in the user interface. For example, if you have multiple sites that produce
side effects on the same channel, you will want to label the different sites with different labels. This aids the alignment algorithm to intelligently
compare the produced side effects. One possible label is the code address location that the side effect is produced at.