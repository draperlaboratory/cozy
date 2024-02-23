Using Concolic Execution
=================================

Concolic execution is a state exploration strategy that uses concrete values to
guide symbolic execution. cozy performs concolic execution slightly differently
than what you might be used to with angr, including angr's Unicorn engine. In
our implementation of concolic execution, concrete values for each symbol are
chosen, and symbolic execution proceeds as normal. When a branch is created in
the symbolic execution, the concrete values are substituted into the constraints
of both children, and the children that evaluate to false are placed in a deferred
stash. Once execution reaches a terminal state, a deferred child is selected using
some heuristic, and its constraints are used to generate a new concrete input.
This is equivalent to negating a portion of the path constraint that you might
typically see in literature on concolic execution. Our core implementation of
concolic execution can be used outside of the cozy workflow as a standalone
exploration technique. The relevant classes if you wish to do this can be found
in the :py:mod:`cozy.concolic.exploration` module.

Since cozy is a comparative framework, we implement an additional strategy
called joint concolic execution. In joint concolic execution, we alternate
between the two programs when generating concrete values. After a concrete value
is implemented, we run both programs on the same concrete values, which automatically
leads to compatible state pairs being generated.

Note that like typical symbolic execution, concolic execution can be complete
if so desired. The execution is complete if there are no deferred states in either
program. However the primary benefit of concolic execution is that we can explore
promising paths at the expense of an incomplete analysis. The promising paths in cozy
are determined by heuristics. There are two different heuristics required for
concolic execution:

1. A termination heuristic, which determines when to halt concolic execution.
2. A candidate heuristic, which determines which deferred state to explore next.

Some pre-made heuristics can be found in :py:mod:`cozy.concolic.heuristics`. Let's
walk through an example of using a joint concolic session to explore how to use
:py:class:`cozy.concolic.session.JointConcolicSession`.

Let's assume that we already have a prepatched and postpatched cozy project set up::

    sess_prepatched = proj_prepatched.session('process_sensor_data')
    add_directives(sess_prepatched)
    initialize_state(sess_orig)

    sess_postpatched = proj_postpatched.session('process_sensor_data')
    add_directives(sess_postpatched)
    initialize_state(sess_postpatched)

We are now ready to create and run a joint concolic session. We must remember to pass
a set of symbols used in the program to the
:py:meth:`~cozy.concolic.session.JoinConcolicSession.run` method, as we need to assign
concrete values to every symbolic value. We also construct the candidate and termination
heuristics::

    joint_sess = JointConcolicSession(sess_prepatched, sess_postpatched,
                                      candidate_heuristic_left=BBTransitionCandidate(),
                                      candidate_heuristic_right=BBTransitionCandidate(),
                                      termination_heuristic_left=CyclomaticComplexityTermination.from_session(sess_prepatched),
                                      termination_heuristic_right=CyclomaticComplexityTermination.from_session(sess_postpatched))
    (prepatched_results, postpatched_results) = joint_sess.run([], [], symbols)

Here we are setting heuristics so that we do not explore every state. Instead, our candidate
heuristic will pick states with the most unique basic block edge transitions in their history,
and the exploration will be terminated once the number of terminal states exceeds the
cyclomatic complexity of the session's function. The return result from the
:py:meth:`~cozy.concolic.session.JoinConcolicSession.run` method gives two
:py:class:`~cozy.session.RunResult` objects, which can be directly be used by
:py:class:`cozy.analysis.Comparison`::

    comparison_results = analysis.Comparison(prepatched_results, postpatched_results)

We can of course visualize the results in the browser::

    # Here args is not the function arguments, but rather the contents of the memory
    # mutated by initialize_state
    execution_graph.visualize_comparison(proj_prepatched, proj_postpatched,
                                         prepatched_results, postpatched_results,
                                         comparison_results,
                                         concrete_arg_mapper=concrete_mapper, args=args,
                                         num_examples=2, open_browser=True)

The full implementation used in this guide can be found at
https://github.com/draperlaboratory/cozy/blob/main/examples/cmp_weather_v5_concolic.py