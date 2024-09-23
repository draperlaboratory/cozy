Getting Started
=================================

On this page we will cover the architecture of cozy and how you can use
it to compare two binary programs. cozy is based on the angr symbolic
execution framework, so we support the same architectures as angr. We
will be following the null_deref example, which can be found in the
examples and test_programs folder in the cozy repository. The null_deref
source code is a very simple C program which writes the integer 42 to
some location in memory:

**Prepatched null_deref (first program being compared)**::

    #include <stdio.h>

    void my_fun(int *num) {
        *num = 42;
    }

    int main(int argc, char *argv[]) {
        int my_num;
        my_fun(&my_num);
        printf("my_num: %d\n", my_num);
        return 0;
    }

**Postpatched null_deref_patched (second program being compared)**::

    #include <stdio.h>

    void my_fun(int *num) {
        if (num != NULL) {
            *num = 42;
        }
    }

    int main(int argc, char *argv[]) {
        int my_num;
        my_fun(&my_num);
        printf("my_num: %d\n", my_num);
        return 0;
    }

Let's assume that we are compiling for x64 architecture. In this case we
are interested in comparing my_fun between the two programs. Much like angr,
cozy can be used interactively through a Python REPL or through a Python script.

==========================
How cozy makes comparisons
==========================

To make comparisons between two programs with different function
implementations, cozy uses symbolic execution. Both programs are fed
the same symbolic input, and cozy runs symbolic execution until all states
terminate. At the end of execution, we have a list of deadended (terminated)
states from the prepatched program, and a list of deadended states from the
postpatched program. Each of these states have constraints associated with
them that were collected as the program stepped through symbolic execution.

Suppose that we take some state A from the prepatched run, and some state
B from the postpatched run. We say that A and B are *compatible* if the
constraints associated with the A and B are jointly satisfiable. In
pseudocode syntax, this roughly means that the following is True::

    is_sat(A.constraints & B.constraints)

Recall that the input to our functions are symbolic variables, so the
set of constraints is in terms of these symbolic variables. We can think
of the constraints as creating a predicate that exactly determines the
subset of the input that leads to a specific state. Taking the conjunction
of the constraints is therefore equivalent to creating a predicate
that restricts the set of input values to the intersection of the input
set for state A and state B. If this predicate is satisfiable, then
this intersection of sets is nonempty, which means that there is at
least one concrete input that will cause the program to end in state A
in the prepatched program and state B in the postpatched program.

Therefore the naive approach is to compare all pairs of terminal states
from the prepatched and postpatched and check for satisfiability. cozy
makes an optimization by using memoization, so in practice compatibility
checks over most programs should be fast. cozy is also capable of generating
concrete examples, which is useful for generating test cases and
walking through program execution.

===================
Example Walkthrough
===================

Let's open a Python REPL and import the required libraries::

    import cozy
    from cozy.project import Project
    from cozy.directive import Assume, Assert
    import claripy

Let's begin by creating cozy projects for the two programs given
previously. A Project is a cozy class that encapsulates a single
program::

    proj_prepatched = Project("null_deref")
    proj_postpatched = Project("null_deref_patched")

To execute the my_fun function, angr needs to know the function signature
of the functions. This information is typically not retained in the binary,
so we need to determine that with some other method. In this case we have
the source code, so we can add the function signature quite easily::

    proj_prepatched.add_prototype("my_fun", "void f(int *a)")
    proj_postpatched.add_prototype("my_fun", "void f(int *a)")

We now need to create sessions from each project. A session is created
from a specific project, and represents a single run of symbolic
execution. Here we pass "my_fun" to the
:py:meth:`~cozy.project.Project.session` method, which indicates that
we are going to be running the "my_fun" function::

    sess_prepatched = proj_prepatched.session("my_fun")
    sess_postpatched = proj_postpatched.session("my_fun")

Since we will only be comparing the my_fun function, we need to create
the symbolic value to pass to the functions::

    arg0 = claripy.BVS("num_arg", 64)

The symbolic value arg0 has 64 bits because it represents a pointer
on a 64-bit architecture.

Alternatively we could have used the :py:func:`cozy.primitives.sym_ptr` helper
function to create the claripy symbolic variable::

    import archinfo
    arg0 = cozy.primitives.sym_ptr(archinfo.ArchAMD64, "num_arg")

We will now constrain arg0 to be either NULL or be equal to a valid memory
address in our two sessions. Currently angr has limited support for symbolic
memory addressing, so we will malloc space for our integers then constrain
arg0 accordingly::

    addr_prepatched = sess_prepatched.malloc(4) # integers are 4 bytes on the target arch
    sess_prepatched.add_constraints((arg0 == 0x0) | (arg0 == addr_prepatched))
    addr_postpatched = sess_postpatched.malloc(4)
    sess_postpatched.add_constraints((arg0 == 0x0) | (arg0 == addr_postpatched))

So before any execution we have constrained arg0 to be either NULL
(0x0) or a concrete 64-bit address returned by
:py:meth:`~cozy.project.Session.malloc`.

================================
Directives - Assumes and Asserts
================================

cozy provides support for *directives*, which are attached to specific
program instructions. Two basic directives that you should know about
are :py:class:`cozy.directive.Assume` and :py:class:`cozy.directive.Assert`.
Assume and assert function by pausing execution once a specific instruction
is reached and adding constraints to the SMT solver. Assumes are used for
adding preconditions, and are often set to be triggered at the start of
functions. Asserts are triggered if there exists an input that will cause
the assert to evaluate to false. Note that directives do not change the
code being executed: they work more or less in the same way as debug
breakpoints.

To demonstrate that a null dereference can occur in the prepatched binary
and not in the postpatched binary, let's add asserts to specific addresses.
Running the binaries through a tool like Ghidra reveals that the NULL
dereference occurs at an offset of 0x10 from the start of my_fun in the
prepatched binary. At this point the address being dereferenced is stored
in the RAX register. Let's create a directive that encodes these observations::

    mem_write_okay_prepatched = Assert.from_fun_offset(
            project=proj_prepatched,
            fun_name="my_fun",
            offset=0x10,
            condition_fun=lambda state: state.regs.rax != 0x0,
            info_str="Dereferencing null pointer"
        )

When execution reaches my_fun+0x10, the evaluation will be halted and
cozy will pass the angr.SimState to the condition_fun and will check to see
if it is possible to find an input value that will trigger the condition.
Let's add the directive to the prepatch session::

    sess_prepatched.add_directives(mem_write_okay_prepatched)

Let's invoke the prepatched my_fun with arg0 as the symbolic input via the
:py:meth:`~cozy.project.Session.run` method::

    run_result = sess_prepatched.run([arg0])
    print(run_result)

Which prints the following result that informs us that an assertion was triggered::

    RunResult(1 deadended, 0 errored, 1 asserts_failed, 0 assume_warnings, 0 postconditions_failed, 0 spinning)

To view a report on what went wrong with the assertion, let's create
a report using the :py:meth:`~cozy.project.RunResult.report_asserts_failed`
method::

    print(run_result.report([arg0]))

Which prints off the human-readable report::

    Errored Report:
    No errored states

    Asserts Failed Report:
    Assert for address 0x401179 was triggered: <Bool int_arg_0_64 != 0x0>
    Dereferencing null pointer
    Here are 1 concrete input(s) for this particular assertion:
    1.
        [<BV64 0x0>]

    Postconditions Failed Report:
    No postcondition failure triggered

    Spinning (Looping) States Report:
    No spinning states were reported

As part of the report, cozy reports that the concretized input that leads to
this assertion being triggered occurs when the input argument is 0.

Now let's make another assert for the postpatched session and verify
that no NULL dereference occurs in the postpatch::

    mem_write_okay_postpatched = Assert.from_fun_offset(
            project=proj_postpatched,
            fun_name="my_fun",
            offset=0x17,
            condition_fun=lambda state: state.regs.rax != 0x0,
            info_str="Dereferencing null pointer"
        )
    sess_postpatched.add_directives(mem_write_okay_postpatched)
    run_result = sess_postpatched.run()
    print(run_result)

In the console we see that no assertions were triggered::

    RunResult(1 deadended, 0 errored, 0 asserts_failed, 0 assume_warnings, 0 postconditions_failed)

======================
Making the Comparisons
======================

To compare two program executions, we need two :py:class:`cozy.project.RunResult` objects.
Let's create fresh sessions and re-run without any directives attached. This time we will make use of
:py:func:`primitive.sym_ptr_constraints` to generate the constraints instead of creating them manually::

    sess_prepatched = proj_prepatched.session("my_fun")
    sess_postpatched = proj_postpatched.session("my_fun")
    addr_prepatched = sess_prepatched.malloc(cozy.constants.INT_SIZE)
    sess_prepatched.add_constraints(cozy.primitives.sym_ptr_constraints(arg0, addr_prepatched, can_be_null=True))
    addr_postpatched = sess_postpatched.malloc(cozy.constants.INT_SIZE)
    sess_postpatched.add_constraints(cozy.primitives.sym_ptr_constraints(arg0, addr_postpatched, can_be_null=True))

Now let's run both of our new sessions::

    prepatched_result = sess_prepatched.run([arg0])
    postpatched_result = sess_postpatched.run([arg0])

We can inspect the results object to see how many states we are dealing with::

    print(prepatched_result)
    print(postpatched_result)

This prints the following messages::

    RunResult(1 deadended, 0 errored, 0 asserts_failed, 0 assume_warnings, 0 postconditions_failed, 0 spinning)
    RunResult(2 deadended, 0 errored, 0 asserts_failed, 0 assume_warnings, 0 postconditions_failed, 0 spinning)

We can now make a comparison between these two terminated results. Constructing a Comparison object is used to do
the comparison computation::

    comparison_results = cozy.analysis.Comparison(prepatched_result, postpatched_result, simplify=True)

To view a human readable report, we can now call the :py:meth:`cozy.analysis.Comparison.report` method, which
will convert the :py:class:`~cozy.analysis.Comparison` to a human readable summary::

    print(comparison_results.report([arg0]))

We now see the human readable report

.. code-block:: text
    :linenos:

    STATE PAIR (0, DEADENDED_STATE), (0, DEADENDED_STATE) are different
    Memory difference detected for 0,0:
    {'range(0x0, 0x4)': (<BV32 0x2a000000>, <BV32 0x0>)}
    Instruction pointers for these memory writes:
    {'range(0x0, 0x4)': (frozenset({<BV64 0x401179>}), frozenset())}
    Register difference detected for 0,0:
    {'eflags': (<BV64 0x0>, <BV64 0x44>), 'flags': (<BV64 0x0>, <BV64 0x44>), 'rflags': (<BV64 0x0>, <BV64 0x44>)}
    Here are 1 concrete input(s) for this particular state pair:
    1.
        Input arguments: [<BV64 0x0>]
        Concrete mem diff: {'range(0x0, 0x4)': (<BV32 0x2a000000>, <BV32 0x0>)}
        Concrete reg diff: {'eflags': (<BV64 0x0>, <BV64 0x44>), 'flags': (<BV64 0x0>, <BV64 0x44>), 'rflags': (<BV64 0x0>, <BV64 0x44>)}

    STATE PAIR (0, DEADENDED_STATE), (1, DEADENDED_STATE) are different
    The memory was equal for this state pair
    Register difference detected for 0,1:
    {'eflags': (<BV64 0x0>, <BV64 0x4>), 'flags': (<BV64 0x0>, <BV64 0x4>), 'rflags': (<BV64 0x0>, <BV64 0x4>)}
    Here are 1 concrete input(s) for this particular state pair:
    1.
        Input arguments: [<BV64 0xc0000000>]
        Concrete reg diff: {'eflags': (<BV64 0x0>, <BV64 0x4>), 'flags': (<BV64 0x0>, <BV64 0x4>), 'rflags': (<BV64 0x0>, <BV64 0x4>)}

    There are no prepatched orphans
    There are no postpatched orphans

We can see that cozy found a diff between the 0th deadended
(terminated) state in the prepatched program (we will refer to this
state as s0) and the 0th deadended state in the postpatched program
(we will refer to this state as s0'). Together these two states form a
state pair, which is displayed on line 1 of the report. As we will see
from the following lines of the report, s0 represents the sole final
symbolic state for the prepatched function (there is only one path
through this function), and s0' represents the final state for the
"false" branch of the postpatched function (i.e., the path that is
triggered by a NULL argument).

Line 3 displays the memory addresses that are different. Contents of
memory for written ranges are mapped to a tuple containing the
symbolic bytes at those addresses as a (prepatched, postpatched)
tuple. In this case, memory at addresses 0x0 to 0x4 is 0x2a000000 in
s0 (because the prepatched function writes 0x2a = 42 to the NULL
address), and 0x0 in s0' (because the NULL check prevents the write
from occurring).

Line 5 tells the instruction pointer the program was at when it wrote
to those specific memory address ranges.  Here we see that the
prepatched program was at the instruction 0x401179 when it wrote to
address 0x0, and the postpatched program never wrote to that address
(hence the empty frozenset).

Line 7 gives the symbolic register difference between the states. As we can see, the flags registers
are different due to the presence of a branch in the postpatched program. As with the memory, each register
maps to a (prepatched, postpatched) tuple which gives the symbolic contents of the registers.

Lines 8-12 gives concretized input that will cause the prepatched program to end in state s0 and
the postpatched program in state s0'. The input argument is concretized to 0x0 (aka NULL). Additionally since
the memory contents and register contents may be symbolic, we provide a concretized version of those as well.

Lines 14-21 tells us that there is another diff for the state pair
(0,1). The second state in this pair represents the "true" branch
through the postpatched function. In this case we observe that the
only difference is in the flags registers, and that there are no
observable differences in memory. The concrete input argument for this
pair is when the input is non-NULL.

The next lines describe any orphaned states - typically there will be none. An orphaned state is a state in which
there are no compatible pair states.

================
Further Examples
================

Further examples on how to use cozy for some simple programs can be found at https://github.com/draperlaboratory/cozy/tree/main/examples
