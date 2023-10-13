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
the same symbolic input, and cozy runs symbolic execuction until all states
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
of the constrains is therefore equivalent to creating a predicate
that restricts the set of input values to the intersection of the input
set for state A and state B. If this predicate is satisfiable, then
this intersection of sets is nonempty, which means that there is at
least one concrete input that will cause the program to end in state A
in the prepatched program and state B in the postpatched program.

Therefore the naive approach is to compare all pairs of deadended states
from the prepatched and postpatched and check for satisfiability. cozy
makes an optimization by checking ancestor (ie, nonterminal) states
and checking for compatibility. cozy is also capable of generating
concrete examples, which is very useful for generating test cases and
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
from a specific project, and represents a single execution run. Here we pass
"my_fun" to the :py:meth:`~cozy.project.Project.session` method, which indicates that we are going to be running
the "my_fun" function::

    sess_prepatched = proj_prepatched.session("my_fun")
    sess_postpatched = proj_postpatched.session("my_fun")

Since we will only be comparing the my_fun function, we need to create
the symbolic value to pass to the functions::

    arg0 = claripy.BVS("num_arg", 64)

We will now constrain arg0 to be either NULL or be equal to a valid memory
address in our two sessions. Currently angr has limited support for symbolic
memory addressing, so we will malloc space for our integers then constrain
arg0 accordingly::

    addr_prepatched = sess_prepatched.malloc(4)
    sess_prepatched.add_constraints((arg0 == 0x0) | (arg0 == addr_prepatched))
    addr_postpatched = sess_postpatched.malloc(4)
    sess_postpatched.add_constraints((arg0 == 0x0) | (arg0 == addr_postpatched))

So before any execution we have constrained arg0 to be NULL (0x0) or be
a concrete address returned by :py:meth:`~cozy.project.Session.malloc`.

================================
Directives - Assumes and Asserts
================================

cozy provides support for *directives*, which are attached to specific
program instructions. Two basic directives that you should know about
are :py:class:`cozy.directive.Assume` and :py:class:`cozy.directive.Assert`.
Assume and assert function by pausing execution once a specific instruction
is reached and add constraints to the SMT solver. Assumes are used for
adding preconditions, and are often set to be triggered at the start of
functions. Asserts are triggered if there exists an input that will cause
the assert to be evaluated to true. Note that directives do not change the
code being executed: they work more or less in the same way as debug
breakpoints.

To demonstrate that a null dereference can occur in the prepatched binary
and not in the postpatched binary, let's add asserts to specific addresses.
Running the binaries through a tool like Ghidra reveals that the NULL
dereference occurs at an offset of 0x10 from the start of my_fun in the
prepatched binary. At this point the address being dereferenced is stored
in the RAX register. Let's create a directive that encodes these observations::

    mem_write_okay_prepatched = Assert(
            project=proj_prepatched,
            fun_name="my_fun",
            offset=0x10,
            condition_fun=lambda st: st.regs.rax != 0x0,
            info_str="Dereferencing null pointer"
        )

When execution reaches my_fun+0x10, the evaluation will be halted and
cozy will pass the state to the condition_fun and will check to see
if it is possible to find an input value that will trigger the condition.
Let's add the directive to the prepatch session::

    sess_prepatched.add_directives(mem_write_okay_prepatched)

Let's invoke the prepatched my_fun with arg0 as the symbolic input via the
:py:meth:`~cozy.project.Session.run` method::

    sess_prepatched.run(arg0)

In the console we see the following message, indicating that the assert was
triggered::

    Checking Assert...
    Assert for address 0x401179 was triggered: <Bool num_arg_102_64 != 0x0>
    Dereferencing null pointer
    <cozy.project.AssertFailed object at 0x7effa73faa50>

Additionally we note that the :py:meth:`~cozy.project.Session.run` method
returned a :py:class:`cozy.project.AssertFailed` object.

Now let's make another assert for the postpatched session and verify
that no NULL dereference occurs in the postpatch::

    mem_write_okay_postpatched = Assert(
            project=proj_postpatched,
            fun_name="my_fun",
            offset=0x17,
            condition_fun=lambda st: st.regs.rax != NULL_PTR,
            info_str="Dereferencing null pointer"
        )
    sess_postpatched.add_directives(mem_write_okay_postpatched)
    sess_postpatched.run()

In the console we see the following message, indicating that no asserts were
triggered::

    No asserts triggered!
    <cozy.project.TerminatedResult object at 0x7effa723c410>

Additionally we get a :py:class:`cozy.project.TerminatedResult`
object from the :py:meth:`~cozy.project.Session.run` method.