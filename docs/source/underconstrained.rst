Underconstrained Execution
=================================

.. warning::
    Underconstrained symbolic execution is currently an experimental feature and may
    not be as stable as typical symbolic execution.

Underconstrained symbolic execution is a symbol creation and management strategy
that enables execution that requires a minimal amount of set up. In ordinary cozy
symbolic execution, harnesses must be written to set up the input for the programs
being tested. These harnesses can be tedious to write, and require some reverse
engineering effort to write. Underconstrained execution drastically cuts down
on harness creation time.

In underconstrained execution, the initial registers and memory are entirely symbolic.
This means that setting up the arguments and related data structures is not required.
For simple cases this is fine, however in some scenarios constraints on inputs
are required to ensure that program execution is finite. For these scenarios
underconstrained execution is not suitable.

Let's take a look at some examples of how to use underconstrained symbolic execution::

    sess_prepatched = proj_prepatched.session('my_fun', underconstrained_execution=True)
    results_prepatched = sess_prepatched.run()
    sess_postpatched = proj_postpatched.session('my_fun', underconstrained_execution=True,
        underconstrained_initial_state=results_prepatched.underconstrained_machine_state)
    results_postpatched = sess_postpatched.run()
    comparison = cozy.analysis.Comparison(results_prepatched, results_postpatched)

Here is a summary of the new features that are used for underconstrained execution:

#. We must enable underconstrained execution by setting `underconstrained_execution` to `True` when creating a :py:meth:`~cozy.project.Project.session`.
#. We do not pass any arguments to the :py:meth:`~cozy.session.Session.run` method. The underconstrained initial registers and memory allows the execution to evaluate all possible input values.
#. When we create the second session, we must pass the machine state from the first session by passing a :py:class:`~cozy.session.UnderconstrainedMachineState` object. This object is easily obtained by getting it from the `underconstrained_machine_state` property from the :py:class:`~cozy.session.RunResult` of the previous execution. The :py:class:`~cozy.session.UnderconstrainedMachineState` object is used to ensure that the initial symbolic registers and memory layout is the same between the two executions.

Underconstrained execution employs concretization strategies to concretize symbolic pointers
and symbolic arrays. The strategy employed is based off of the angr
:py:class:`angr.concretization_strategies.SimConcretizationStrategyNorepeatsRange` strategy.
In this strategy, pointers that are symbolic are concretized to fresh areas of memory. This
strategy makes the assumption that pointers shouldn't be aliasing and can in fact point to
different data structures. Pointers for arrays likewise will be concretized to a contiguous
fresh chunk of memory.

This introduces an initial difficulty to diff analysis. Since these fresh chunks of memory are
allocated as needed (on demand), memory layout between two runs needs to be consistent for the comparison
process. This is why an `underconstrained_initial_state` must be passed to the second session's
run.