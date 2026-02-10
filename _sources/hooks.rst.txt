Dealing with Hooks
==================

Some of the default C library hooks provided by angr will not function properly with
comparitive symbolic execution, including joint concolic execution. The issue stems
from two different factors:

1. Hooks may provide an incomplete implementation of the C library hooks, or the complete
implementation may be disabled by default. For example, the ``strtok_r`` function's
more complete implementation may be disabled by default, and should be enabled by setting
:py:attr:`angr.SimState.libc.simple_strtok` to False. Likewise the ``strstr`` libc function
has a configuration option :py:attr:`angr.SimState.libc.max_symbolic_strstr` which is by
default set to a very conservative value of 1.

2. The default angr hooks create fresh symbolic variables, and constrain these symbolic
values by adding to the state's constraints. This is problematic since in comparitive
symbolic execution we assume that both programs are fed the same symbolic variables.
Fortunately it is possible to eliminate the fresh symbolic variables in most cases. To see
an example of how to do this, see our provided replacement hook for ``strlen`` at
:py:class:`cozy.hooks.strlen.strlen`.

In general, the best strategy for dealing with hooks is to be aware of their limitations,
understand the configuration options found in :py:attr:`angr.SimState.libc`, and replace
the default hooks when needed.

To replace a hook for a specific project, you may use the
:py:meth:`cozy.project.Project.hook_symbol` method.