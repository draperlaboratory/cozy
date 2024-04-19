import sys
from collections.abc import Callable

import portion as P

import angr, claripy
from angr import SimStateError, SimState
from angr.sim_manager import ErrorRecord, SimulationManager

from . import log, side_effect
from .directive import Directive, Assume, Assert, VirtualPrint, ErrorDirective, AssertType, Breakpoint, Postcondition
from .terminal_state import AssertFailedState, ErrorState, DeadendedState, PostconditionFailedState, SpinningState
import cozy

class RunResult:
    """
    This class is used for storing the results of running a session.

    :ivar list[DeadendedState] deadended: States that reached normal termination.
    :ivar list[ErrorState] errored: States that reached an error state. This may be triggered for example by program\
    errors such as division by 0, or by reaching a :py:class:`cozy.directive.ErrorDirective`.
    :ivar list[AssertFailed] asserts_failed: States where an assertion was able to be falsified.
    :ivar list[tuple[Assume, SimState]] assume_warnings: An assume warning occurs when a\
    :py:class:`~cozy.directive.Assume` is reached, and the added assumption contradicts the constraints for that state.\
    This means that due to the assumption, the new constraints are not satisfiable.
    :ivar list[PostconditionFailedState] postconditions_failed: States where the function returned, and the assertion\
    as part of the postcondition could be falsified.
    :ivar list[SpinningState] spinning: States that were stashed due to a loop bound being breached.
    """
    def __init__(self, deadended: list[DeadendedState], errored: list[ErrorState],
                 asserts_failed: list[AssertFailedState], assume_warnings: list[tuple[Assume, SimState]],
                 postconditions_failed: list[PostconditionFailedState],
                 spinning: list[SpinningState]):
        self.deadended = deadended
        self.errored = errored
        self.asserts_failed = asserts_failed
        self.assume_warnings = assume_warnings
        self.postconditions_failed = postconditions_failed
        self.spinning = spinning

    @property
    def assertion_triggered(self) -> bool:
        """
        Returns True if there were any assertions triggered during this run.

        :return: True if there were assertions triggered.
        :rtype: bool
        """
        return len(self.asserts_failed) > 0

    @property
    def postcondition_triggered(self) -> bool:
        """
        Returns True if there were any postcondition assertions triggered during this run.

        :return: True if there were postcondition assertions triggered.
        :rtype: bool
        """
        return len(self.postconditions_failed) > 0

    def __str__(self):
        return "RunResult({} deadended, {} errored, {} asserts_failed, {} assume_warnings, {} postconditions_failed, {} spinning)".format(len(self.deadended), len(self.errored), len(self.asserts_failed), len(self.assume_warnings), len(self.postconditions_failed), len(self.spinning))

    def report(self, args: any, concrete_post_processor: Callable[[any], any] | None = None, num_examples: int = 3) -> str:
        """
        Creates a composite human readable report with information about errored states, asserts failed,\
        postconditions failed, and spinning states.

        :param any args: The arguments to concretize
        :param Callable[[any], any] | None concrete_post_processor: This function is used to post-process concretized\
        versions of args before they are added to the return string. Some examples of this function include converting\
        an integer to a negative number due to use of two's complement, or slicing off parts of the argument based on\
        another part of the input arguments.
        :param int num_examples: The maximum number of concrete examples to show the user.
        :return: The report as a string
        :rtype: str
        """
        e_report = self.report_errored(args, concrete_post_processor=concrete_post_processor, num_examples=num_examples)
        a_report = self.report_asserts_failed(args, concrete_post_processor=concrete_post_processor, num_examples=num_examples)
        p_report = self.report_postconditions_failed(args, concrete_post_processor=concrete_post_processor, num_examples=num_examples)
        s_report = self.report_spinning(args, concrete_post_processor=concrete_post_processor, num_examples=num_examples)
        output = "Errored Report:\n{}\n\nAsserts Failed Report:\n{}\n\nPostconditions Failed Report:\n{}\n\nSpinning (Looping) States Report:\n{}".format(e_report, a_report, p_report, s_report)
        return output

    def report_errored(self, args: any, concrete_post_processor: Callable[[any], any] | None = None, num_examples: int = 3) -> str:
        """
        Creates a human readable report about a list of errored states.

        :param any args: The arguments to concretize
        :param Callable[[any], any] | None concrete_post_processor: This function is used to post-process concretized\
        versions of args before they are added to the return string. Some examples of this function include converting\
        an integer to a negative number due to use of two's complement, or slicing off parts of the argument based on\
        another part of the input arguments.
        :param int num_examples: The maximum number of concrete examples to show the user for each errored state.
        :return: The report as a string
        :rtype: str
        """
        if len(self.errored) == 0:
            return "No errored states"
        else:
            output = ""
            for err in self.errored:
                output += "Error State #{}\n".format(err.state_id)
                output += "{}\n".format(err.error)
                concrete_vals_lst = err.concrete_examples(args, num_examples=num_examples)
                output += "Here are {} concrete input(s):\n".format(len(concrete_vals_lst))
                for (j, concrete_input) in enumerate(concrete_vals_lst):
                    if concrete_post_processor is not None:
                        concrete_args = concrete_post_processor(concrete_input.args)
                    else:
                        concrete_args = concrete_input.args
                    output += "{}.\n".format(j + 1)
                    output += "\t{}\n".format(str(concrete_args))
                output += "\n"
            return output

    def report_spinning(self, args: any, concrete_post_processor: Callable[[any], any] | None = None, num_examples: int = 3) -> str:
        """
        Creates a human readable report about a list of failed postcondition assertions.

        :param any args: The arguments to concretize
        :param Callable[[any], any] | None concrete_post_processor: This function is used to post-process concretized\
        versions of args before they are added to the return string. Some examples of this function include converting\
        an integer to a negative number due to use of two's complement, or slicing off parts of the argument based on\
        another part of the input arguments.
        :param int num_examples: The maximum number of concrete examples to show the user for each assertion failed\
        state.
        :return: The report as a string
        :rtype: str
        """
        if len(self.spinning) == 0:
            return "No spinning states were reported"
        else:
            output = ""
            for state in self.spinning:
                output += "Spinning State #{}\n".format(state.state_id)
                concrete_inputs = state.concrete_examples(args, num_examples)
                output += "Here are {} concrete input(s) for this particular postcondition assertion:\n".format(len(concrete_inputs))
                for (i, concrete_input) in enumerate(concrete_inputs):
                    if concrete_post_processor is not None:
                        concrete_args = concrete_post_processor(concrete_input.args)
                    else:
                        concrete_args = concrete_input.args
                    output += "{}.\n".format(i + 1)
                    output += "\t{}\n".format(str(concrete_args))
                    if len(concrete_input.side_effects) > 0:
                        output += "Side effects:\n"
                        for (channel, effects) in concrete_input.side_effects.items():
                            output += "Channel {}:\n".format(channel)
                            for eff in effects:
                                output += str(eff.mapped_body) + "\n"
                output += "\n\n"
            return output

    def report_postconditions_failed(self, args: any, concrete_post_processor: Callable[[any], any] | None = None, num_examples: int = 3) -> str:
        """
        Creates a human readable report about the failed postcondition assertions.

        :param any args: The arguments to concretize
        :param Callable[[any], any] | None concrete_post_processor: This function is used to post-process concretized\
        versions of args before they are added to the return string. Some examples of this function include converting\
        an integer to a negative number due to use of two's complement, or slicing off parts of the argument based on\
        another part of the input arguments.
        :param int num_examples: The maximum number of concrete examples to show the user for each assertion failed\
        state.
        :return: The report as a string
        :rtype: str
        """
        if len(self.postconditions_failed) == 0:
            return "No postcondition failure triggered"
        else:
            output = ""
            for state in self.postconditions_failed:
                output += "Postcondition failure was triggered: {}\n".format(str(state.cond))
                if state.postcondition.info_str is not None:
                    output += state.postcondition.info_str + "\n"
                concrete_inputs = state.concrete_examples(args, num_examples)
                output += "Here are {} concrete input(s) for this particular postcondition assertion:\n".format(len(concrete_inputs))
                for (i, concrete_input) in enumerate(concrete_inputs):
                    if concrete_post_processor is not None:
                        concrete_args = concrete_post_processor(concrete_input.args)
                    else:
                        concrete_args = concrete_input.args
                    output += "{}.\n".format(i + 1)
                    output += "\t{}\n".format(str(concrete_args))
                    if len(concrete_input.side_effects) > 0:
                        output += "Side effects:\n"
                        for (channel, effects) in concrete_input.side_effects.items():
                            output += "Channel {}:\n".format(channel)
                            for eff in effects:
                                output += str(eff.mapped_body) + "\n"
                output += "\n\n"
            return output

    def report_asserts_failed(self, args: any, concrete_post_processor: Callable[[any], any] | None = None, num_examples: int = 3) -> str:
        """
        Creates a human readable report about any failed assertions.

        :param any args: The arguments to concretize
        :param Callable[[any], any] | None concrete_post_processor: This function is used to post-process concretized\
        versions of args before they are added to the return string. Some examples of this function include converting\
        an integer to a negative number due to use of two's complement, or slicing off parts of the argument based on\
        another part of the input arguments.
        :param int num_examples: The maximum number of concrete examples to show the user for each assertion failed\
        state.
        :return: The report as a string
        :rtype: str
        """
        if len(self.asserts_failed) == 0:
            return "No asserts triggered"
        else:
            output = ""
            for state in self.asserts_failed:
                output += "Assert for address {} was triggered: {}\n".format(hex(state.assertion.addr), str(state.cond))
                if state.assertion.info_str is not None:
                    output += state.assertion.info_str + "\n"
                concrete_inputs = state.concrete_examples(args, num_examples)
                output += "Here are {} concrete input(s) for this particular assertion:\n".format(len(concrete_inputs))
                for (i, concrete_input) in enumerate(concrete_inputs):
                    if concrete_post_processor is not None:
                        concrete_args = concrete_post_processor(concrete_input.args)
                    else:
                        concrete_args = concrete_input.args
                    output += "{}.\n".format(i + 1)
                    output += "\t{}\n".format(str(concrete_args))
                    if len(concrete_input.side_effects) > 0:
                        output += "Side effects:\n"
                        for (channel, effects) in concrete_input.side_effects.items():
                            output += "Channel {}:\n".format(channel)
                            for eff in effects:
                                output += str(eff.mapped_body) + "\n"
                output += "\n\n"
            return output

# This on_mem_write is designed to be attached as a breakpoint that is triggered
# whenever memory is written. This hook simply logs the current instruction pointer
# for each written byte in state.globals['mem_writes']

_mem_write_ctr = 0

def _on_mem_write(state):
    # We use _mem_write_ctr to stop the IntervalDict from merging together adjacent intervals
    # For example if we do the following the intervals will be merged:
    # d = I.IntervalDict()
    # d[I.closedopen(0,3)] = set()
    # d[I.closedopen(3,5)] = set()
    # d
    # >>> {[0,5): set()}
    # We want to prevent that from happening
    global _mem_write_ctr
    if 'mem_writes' in state.globals:
        mem_writes = state.globals['mem_writes'].copy()
    else:
        mem_writes = P.IntervalDict()
    sym_start_addr = state.inspect.mem_write_address
    if isinstance(sym_start_addr, claripy.ast.BV):
        if sym_start_addr.concrete:
            start_addrs = [sym_start_addr.concrete_value]
        else:
            # The write address is symbolic. Choose 16 arbitrary concrete solutions
            start_addrs = [solution.concrete_value for solution in state.solver.eval_to_ast(sym_start_addr, 16)]
    elif isinstance(sym_start_addr, int):
        start_addrs = [sym_start_addr]
    else:
        start_addrs = None
    length = state.inspect.mem_write_length
    if isinstance(length, claripy.ast.BV):
        if length.concrete:
            length = length.concrete_value
        else:
            # TODO: Do something better than take the max
            length = state.solver.max(length)
    ip_frozenset = frozenset([state.ip])
    if start_addrs is not None and length is not None:
        for st_addr in start_addrs:
            write_range = P.closedopen(st_addr, st_addr + length)
            if len(start_addrs) > 1:
                existing_ip = [ip_set for (n, ip_set) in mem_writes[write_range].values()]
                new_ip = ip_frozenset.union(*existing_ip)
                mem_writes[write_range] = (_mem_write_ctr, new_ip)
                _mem_write_ctr += 1
            else:
                mem_writes[write_range] = (_mem_write_ctr, ip_frozenset)
                _mem_write_ctr += 1
    state.globals['mem_writes'] = mem_writes

_malloc_name_ctr = 0

def _on_simprocedure(state):
    global _malloc_name_ctr
    if state.inspect.simprocedure_name == "malloc":
        num_bytes = state.inspect.simprocedure.arguments[0]
        max_num_bytes = state.solver.max(num_bytes)
        name = "malloced_{}_bytes_{}".format(max_num_bytes, _malloc_name_ctr)
        if 'malloced_names' in state.globals:
            malloc_calls = state.globals['malloced_names'].copy()
        else:
            malloc_calls = P.IntervalDict()
        addr = state.inspect.simprocedure_result
        interval = P.closedopen(addr, addr + max_num_bytes)
        malloc_calls[interval] = (name, interval)
        _malloc_name_ctr += 1
        state.globals['malloced_names'] = malloc_calls

def _save_states(states):
    for state in states:
        state.history.cozy_stdout = state.posix.dumps(sys.stdout.fileno())
        state.history.cozy_stderr = state.posix.dumps(sys.stderr.fileno())
        state.history.cozy_side_effects = state.globals['side_effects']
        if state.project.simos.is_syscall_addr(state.addr):
            # Here we are inside of a syscall implementation. The address that
            # angr jumps to when it executes a syscall does not actually contain
            # the code that is executed. Instead a Python hook is executed
            # to simulate the syscall.
            state.history.cozy_contents = ""
        else:
            try:
                state.history.cozy_contents = state.block()
            except angr.errors.SimEngineError as exc:
                state.history.cozy_contents = ""
        state.history.cozy_constraints = state.solver.constraints

class _SessionExploration:
    def __init__(self, session: 'Session', cache_intermediate_info: bool=True):
        self.session = session
        self.assume_warnings: list[tuple[Assume, SimState]] = []
        # Note that we use a separate list here instead of a new stash because we want to keep around more information
        # about the failed assertion than just the SimState
        self.asserts_failed: list[AssertFailedState] = []
        self.cache_intermediate_info = cache_intermediate_info
        self.asserts_to_scrub: set[Assert] = set()
        self.postconditions_failed: list[PostconditionFailedState] = []
        self.postconditions_to_scrub : set[Postcondition] = set()

    def explore(self, simgr):
        raise NotImplementedError()

class _SessionDirectiveExploration(_SessionExploration):
    def check_postconditions(self, simgr):
        prune_states = set()
        add_states = set()

        postcondition_directives = [directive for directive in self.session.directives if isinstance(directive, Postcondition)]
        for found_state in simgr.deadended:
            for directive in postcondition_directives:
                cond = directive.condition_fun(found_state)
                if directive.assert_type == AssertType.ASSERT_MUST:
                    # Split execution into two states: one where the assertion holds and one where it
                    # doesn't hold
                    true_branch = found_state.copy()
                    true_branch.add_constraints(cond)
                    add_states.add(true_branch)

                    # To check for validity, we need to check that (not cond) is unsatisfiable
                    false_branch = found_state.copy()
                    false_branch.add_constraints(~cond)

                    try:
                        is_sat = false_branch.satisfiable()
                    except claripy.ClaripyZ3Error as err:
                        cozy.log.error("Unable to solve SMT formula when checking postcondition assertion. The SMT solver returned unknown instead of SAT or UNSAT. We will assume that it is possible for the postcondition to fail.\nThe information string attached to the postcondition is: {}\nThe exception thrown was:\n{}", directive.info_str, str(err))
                        is_sat = True
                    except claripy.ClaripySolverInterruptError as err:
                        cozy.log.error("Unable to solve SMT formula when checking postcondition assertion. The SMT solver was interrupted, most likely due to resource exhaustion. We will assume that it is possible for the postcondition to fail.\nThe information string attached to the postcondition is: {}\nThe exception thrown was:\n{}", directive.info_str, str(err))
                        is_sat = True

                    if is_sat:
                        if self.cache_intermediate_info:
                            _save_states([false_branch])
                        # If the false branch is satisfiable, add it to the list of failed assert states
                        # This essentially halts execution on the false branch
                        af = PostconditionFailedState(directive, cond, false_branch, len(self.postconditions_failed))
                        self.postconditions_failed.append(af)
                        # If false_branch is not satisfiable, then there is no way for the assertion to fail.
                    # In any case, we should prune out the original state
                    prune_states.add(found_state)
                elif directive.assert_type == AssertType.ASSERT_CAN or directive.assert_type == AssertType.ASSERT_CAN_GLOBAL:
                    # ASSERT_CAN can be thought of a "catch and release", the original state should
                    # continue execution regardless of what happens
                    true_branch = found_state.copy()
                    true_branch.add_constraints(cond)

                    try:
                        is_sat = true_branch.satisfiable()
                    except claripy.ClaripyZ3Error as err:
                        cozy.log.error("Unable to solve SMT formula when checking postcondition assertion. The SMT solver returned unknown instead of SAT or UNSAT. We will assume that it is possible for the postcondition to fail.\nThe information string attached to the postcondition is: {}\nThe exception thrown was:\n{}", directive.info_str, str(err))
                        is_sat = False
                    except claripy.ClaripySolverInterruptError as err:
                        cozy.log.error("Unable to solve SMT formula when checking postcondition assertion. The SMT solver was interrupted, most likely due to resource exhaustion. We will assume that it is possible for the postcondition to fail.\nThe information string attached to the postcondition is: {}\nThe exception thrown was:\n{}", directive.info_str, str(err))
                        is_sat = False

                    if not is_sat:
                        if self.cache_intermediate_info:
                            _save_states([true_branch])
                        af = PostconditionFailedState(directive, cond, true_branch, len(self.postconditions_failed))
                        self.postconditions_failed.append(af)
                    else:
                        if directive.assert_type == AssertType.ASSERT_CAN_GLOBAL:
                            self.postconditions_to_scrub.add(directive)

        simgr.move(from_stash='deadended', to_stash='pruned', filter_func=lambda state: state in prune_states)

        _save_states(add_states)
        for state in add_states:
            simgr.deadended.append(state)

    def explore(self, simgr):
        addrs_to_directive = {}
        for directive in self.session.directives:
            if hasattr(directive, 'addr'):
                if directive.addr in addrs_to_directive:
                    addrs_to_directive[directive.addr].append(directive)
                else:
                    addrs_to_directive[directive.addr] = [directive]

        find_addrs = set(addrs_to_directive.keys())

        while len(simgr.active) > 0:
            # Explore seems to check the find list BEFORE stepping
            simgr.explore(find=find_addrs, n=1)

            log.info("Running %s: %s", self.session.proj.angr_proj.filename, str(simgr))

            # When using explore with a find key, angr will only put 1 state into the found stash at a time
            # This is problematic since we could create more than one error state triggered for every
            # iteration of the loop. In this case we may never iterate over all the found states before
            # the outer while loop terminates.
            simgr.move(from_stash='active', to_stash='found', filter_func=lambda state: state.addr in find_addrs)

            prune_states = set()
            add_states = set()

            for found_state in simgr.found:
                if found_state.satisfiable():
                    relevant_directives = addrs_to_directive[found_state.addr]
                    for directive in relevant_directives:
                        if isinstance(directive, Assume):
                            cond = directive.condition_fun(found_state)
                            found_state.add_constraints(cond)

                            try:
                                is_sat = found_state.satisfiable()
                            except claripy.ClaripyZ3Error as err:
                                cozy.log.error("Unable to solve SMT state constraints after attaching assume. The SMT solver returned unknown instead of SAT or UNSAT. We will assume that it is possible for the Assume condition to be satisfiable.\nThe information string attached to the Assume is: {}\nThe exception thrown was:\n{}", directive.info_str, str(err))
                                is_sat = True
                            except claripy.ClaripySolverInterruptError as err:
                                cozy.log.error("Unable to solve SMT state constraints after attaching assume. The SMT solver was interrupted, most likely due to resource exhaustion. We will assume that it is possible for the Assume condition to be satisfiable.\nThe information string attached to the Assume is: {}\nThe exception thrown was:\n{}", directive.info_str, str(err))
                                is_sat = True

                            if not is_sat:
                                self.assume_warnings.append((directive, found_state))
                                info_str = "(unknown)" if directive.info_str is None else directive.info_str
                                log.warning(
                                    "Assume %s for address %s was not satisfiable. In this path of execution there is no possible way for execution to proceed past this point: %s",
                                    info_str,
                                    hex(directive.addr),
                                    str(cond))
                        elif isinstance(directive, Assert):
                            cond = directive.condition_fun(found_state)
                            if directive.assert_type == AssertType.ASSERT_MUST:
                                # Split execution into two states: one where the assertion holds and one where it
                                # doesn't hold
                                true_branch = found_state.copy()
                                true_branch.add_constraints(cond)
                                add_states.add(true_branch)

                                # To check for validity, we need to check that (not cond) is unsatisfiable
                                false_branch = found_state.copy()
                                false_branch.add_constraints(~cond)

                                try:
                                    is_sat = false_branch.satisfiable()
                                except claripy.ClaripyZ3Error as err:
                                    cozy.log.error("Unable to solve SMT formula when checking assertion. The SMT solver returned unknown instead of SAT or UNSAT. We will assume that it is possible for the assertion to fail.\nThe information string attached to the assertion is: {}\nThe exception thrown was:\n{}", directive.info_str, str(err))
                                    is_sat = True
                                except claripy.ClaripySolverInterruptError as err:
                                    cozy.log.error("Unable to solve SMT formula when checking assertion. The SMT solver was interrupted, most likely due to resource exhaustion. We will assume that it is possible for the postcondition to fail.\nThe information string attached to the assertion is: {}\nThe exception thrown was:\n{}", directive.info_str, str(err))
                                    is_sat = True

                                if is_sat:
                                    if self.cache_intermediate_info:
                                        _save_states([false_branch])
                                    # If the false branch is satisfiable, add it to the list of failed assert states
                                    # This essentially halts execution on the false branch
                                    af = AssertFailedState(directive, cond, false_branch, len(self.asserts_failed))
                                    self.asserts_failed.append(af)
                                    # If false_branch is not satisfiable, then there is no way for the assertion to fail.
                                # In any case, we should prune out the original state
                                prune_states.add(found_state)
                            elif directive.assert_type == AssertType.ASSERT_CAN or directive.assert_type == AssertType.ASSERT_CAN_GLOBAL:
                                # ASSERT_CAN can be thought of a "catch and release", the original state should
                                # continue execution regardless of what happens
                                true_branch = found_state.copy()
                                true_branch.add_constraints(cond)

                                try:
                                    is_sat = true_branch.satisfiable()
                                except claripy.ClaripyZ3Error as err:
                                    cozy.log.error("Unable to solve SMT formula when checking existential assertion. The SMT solver returned unknown instead of SAT or UNSAT. We will assume that it is possible for the assertion to fail.\nThe information string attached to the postcondition is: {}\nThe exception thrown was:\n{}", directive.info_str, str(err))
                                    is_sat = False
                                except claripy.ClaripySolverInterruptError as err:
                                    cozy.log.error("Unable to solve SMT formula when checking existential assertion. The SMT solver was interrupted, most likely due to resource exhaustion. We will assume that it is possible for the assertion to fail.\nThe information string attached to the postcondition is: {}\nThe exception thrown was:\n{}", directive.info_str, str(err))
                                    is_sat = False

                                if not is_sat:
                                    if self.cache_intermediate_info:
                                        _save_states([true_branch])
                                    af = AssertFailedState(directive, cond, true_branch, len(self.asserts_failed))
                                    self.asserts_failed.append(af)
                                else:
                                    if directive.assert_type == AssertType.ASSERT_CAN_GLOBAL:
                                        self.asserts_to_scrub.add(directive)
                        elif isinstance(directive, VirtualPrint):
                            side_effect.perform(found_state, 'virtual_prints', directive.log_fun(found_state), concrete_post_processor=directive.effect_concrete_post_processor, label=directive.label)
                        elif isinstance(directive, ErrorDirective):
                            prune_states.add(found_state)
                            simgr.errored.append(
                                ErrorRecord(found_state, SimStateError(directive.info_str), sys.exc_info()[2]))
                        elif isinstance(directive, Breakpoint):
                            directive.breakpoint_fun(found_state)
                else:
                    raise RuntimeError(
                        "One of the found states was not satisfiable. This probably shouldn't have happened.")

            # After we are done iterating over the found states, it is now safe to prune the ones that triggered
            # an error
            simgr.move(from_stash='found', to_stash='pruned', filter_func=lambda state: state in prune_states)

            for state in add_states:
                simgr.found.append(state)

            if self.cache_intermediate_info:
                _save_states(simgr.found)
            # We need to step over all the found states so that we don't immediately halt
            # execution of these states in the next interation of the loop
            simgr.step(num_inst=1, stash="found")
            simgr.move(from_stash='found', to_stash="active")
            errored_states = [error_record.state for error_record in simgr.errored]
            if self.cache_intermediate_info:
                _save_states(simgr.active)
                _save_states(errored_states)

        self.check_postconditions(simgr)


class _SessionBasicExploration(_SessionExploration):
    def explore(self, simgr):
        while len(simgr.active) > 0:
            simgr.step()
            log.info("Running %s: %s", self.session.proj.angr_proj.filename, str(simgr))
            if self.cache_intermediate_info:
                _save_states(simgr.active)

class Session:
    """
    A session is a particular run of a project, consisting of attached directives (asserts/assumes).\
    You can malloc memory for storage prior to running the session.\
    Once you are ready to run the session, use the run method.\

    :ivar angr.SimState state: The initial state tied to this particular session. You can access this member to modify\
    properties of the state before a run.
    :ivar cozy.project.Project proj: The Project tied to this session.
    :ivar str | int | None start_fun: The starting function tied to this session. If start_fun is None, then the\
    session starts in an entry state.
    :ivar list[Directive] directives: The directives added to this session.
    :ivar bool has_run: True if the :py:meth:`cozy.project.Session.run` method has been called, otherwise False.
    """
    def __init__(self, proj, start_fun: str | int | None=None):
        """
        Constructs a session derived from a project. The :py:meth:`cozy.project.Project.session` is the preferred method for creating a session, not this constructor.
        """
        self.proj = proj

        self.start_fun = start_fun

        state_options = {
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                angr.options.SYMBOLIC_WRITE_ADDRESSES,
                angr.options.TRACK_MEMORY_ACTIONS,
                angr.options.TRACK_REGISTER_ACTIONS,
            }

        # Create the initial state
        if start_fun is None:
            self.state = self.proj.angr_proj.factory.entry_state(add_options=state_options)
        else:
            self.state = self.proj.angr_proj.factory.blank_state(add_options=state_options)

        self.state.inspect.b('mem_write', when=angr.BP_AFTER, action=_on_mem_write)
        self.state.globals['mem_writes'] = P.IntervalDict()
        self.state.inspect.b('simprocedure', when=angr.BP_AFTER, action=_on_simprocedure)
        self.state.globals['malloced_names'] = P.IntervalDict()
        self.state.globals['side_effects'] = dict()

        # Initialize mutable state related to this session
        self.directives = []
        self.has_run = False

    def store_fs(self, filename: str, simfile: angr.SimFile) -> None:
        """
        Stores a file in a virtual filesystem available during execution. This method simply forwards the arguments\
        to state.fs.insert.

        :param str filename: The filename of the new file.
        :param angr.SimFile simfile: The file to make available to the simulated program.
        :return: None
        :rtype: None
        """
        self.state.fs.insert(filename, simfile)

    def malloc(self, num_bytes: int, name=None) -> int:
        """
        Mallocs a fixed amount of memory using the angr heap simulation plugin. Useful for setting things up in memory\
        before the :py:meth:`~cozy.project.Project.run` method is called.

        :param int num_bytes: The number of bytes to allocate.
        :return: A pointer to the allocated memory block.
        :rtype: int
        """
        global _malloc_name_ctr
        addr = self.state.heap._malloc(num_bytes)
        if name is None:
            name = "malloced_{}_bytes_{}".format(num_bytes, _malloc_name_ctr)
            _malloc_name_ctr += 1
        interval = P.closedopen(addr, addr + num_bytes)
        if 'malloced_names' in self.state.globals:
            malloced_names = self.state.globals['malloced_names']
        else:
            malloced_names = P.IntervalDict()
        malloced_names[interval] = (name, interval)
        self.state.globals['malloced_names'] = malloced_names
        return addr

    def store(self, addr: int, data: claripy.ast.bits, **kwargs):
        """
        Stores data at some address. This method simply forwards the arguments to state.memory.store.

        :param int addr: Address to store the data at.
        :param claripy.ast.bits data: The data to store in memory.
        :param kwargs: Additional keyword arguments to pass to state.memory.store
        """
        self.state.memory.store(addr, data, **kwargs)

    @property
    def memory(self):
        return self.state.memory

    @property
    def mem(self):
        """
        Access memory using a dict-like interface. This property simply forwards to state.mem
        """
        return self.state.mem

    def add_directives(self, *directives: Directive) -> None:
        """
        Adds multiple directives to the session.

        :param Directive directives: The directives to add.
        :return: None
        :rtype: None
        """
        self.directives.extend(directives)

    def add_constraints(self, *constraints: claripy.ast.bool) -> None:
        """
        Adds multiple constraints to the session's state.

        :param claripy.ast.bool constraints: The constraints to add
        :return: None
        :rtype: None
        """
        self.state.add_constraints(*constraints)

    @property
    def start_fun_addr(self):
        # Determine the address of the desired function
        if isinstance(self.start_fun, int):
            return self.start_fun
        elif isinstance(self.start_fun, str):
            return self.proj.find_symbol_addr(self.start_fun)
        else:
            return None

    def _call(self, args: list[claripy.ast.bits], cache_intermediate_info: bool=True,
              ret_addr: int | None=None) -> SimulationManager:
        if self.has_run:
            raise RuntimeError("This session has already been run once. Make a new session to run again.")
        self.has_run = True

        if cache_intermediate_info:
            _save_states([self.state])

        fun_addr = self.start_fun_addr

        if fun_addr is not None:
            if self.start_fun in self.proj.fun_prototypes:
                fun_prototype = self.proj.fun_prototypes[self.start_fun]
            elif fun_addr in self.proj.fun_prototypes:
                fun_prototype = self.proj.fun_prototypes[fun_addr]
            else:
                fun_prototype = None

            kwargs = dict() if ret_addr is None else {"ret_addr": ret_addr}

            state = self.proj.angr_proj.factory.call_state(fun_addr, *args, base_state=self.state,
                                                           prototype=fun_prototype,
                                                           add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                                                                        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                                                                        angr.options.SYMBOLIC_WRITE_ADDRESSES},
                                                           **kwargs)
        else:
            state = self.state

        if cache_intermediate_info:
            _save_states([state])

        # This concretization strategy is necessary for nullable symbolic pointers. The default
        # concretization strategies attempts to concretize to integers within a small (128) byte
        # range. If that fails, it just selects the maximum possible concrete value. This strategy
        # will ensure that we generate up to 128 possible concrete values.
        concrete_strategy = angr.concretization_strategies.SimConcretizationStrategyUnlimitedRange(128)
        state.memory.read_strategies.insert(0, concrete_strategy)
        state.memory.write_strategies.insert(0, concrete_strategy)

        return self.proj.angr_proj.factory.simulation_manager(state)

    def _session_exploration(self, cache_intermediate_info: bool=True) -> _SessionExploration:
        if len(self.directives) > 0:
            return _SessionDirectiveExploration(self, cache_intermediate_info=cache_intermediate_info)
        else:
            return _SessionBasicExploration(self, cache_intermediate_info=cache_intermediate_info)

    def _run_result(self, simgr: SimulationManager, sess_exploration: _SessionExploration) -> RunResult:
        deadended = [DeadendedState(state, i) for (i, state) in enumerate(simgr.deadended)]
        errored = [ErrorState(error_record, i) for (i, error_record) in enumerate(simgr.errored)]
        asserts_failed = [assert_failed for assert_failed in sess_exploration.asserts_failed
                          if assert_failed.assertion not in sess_exploration.asserts_to_scrub]
        postconditions_failed = [postcondition_failed for postcondition_failed in sess_exploration.postconditions_failed
                                 if postcondition_failed not in sess_exploration.postconditions_to_scrub]
        if 'spinning' in simgr.stashes:
            spinning = [SpinningState(state, i) for (i, state) in enumerate(simgr.spinning)]
        else:
            spinning = []

        return RunResult(deadended, errored, asserts_failed, sess_exploration.assume_warnings, postconditions_failed, spinning)

    def run(self, args: list[claripy.ast.bits], cache_intermediate_info: bool=True, ret_addr: int | None=None,
            loop_bound: int | None=None) -> RunResult:
        """
        Runs a session to completion, either starting from the start_fun used to create the session, or from the\
        program start. Note that currently a session may be run only once. If run is called multiple times, a\
        RuntimeError will be thrown.

        :param list[claripy.ast.bits] args: The arguments to pass to the function. angr will utilize the function's\
        type signature to figure out the calling convention to use with the arguments.
        :param bool cache_intermediate_info: If this flag is True, then information about intermediate states will be
        cached. This is required for dumping the execution graph which is used in visualization.
        :param int | None ret_addr: What address to return to if calling as a function
        :param int | None loop_bound: Sets an upper bound on loop iteration count. Useful for programs with\
        non-terminating loops.
        :return: The result of running this session.
        :rtype: RunResult
        """

        simgr = self._call(list(args), cache_intermediate_info=cache_intermediate_info, ret_addr=ret_addr)

        if isinstance(loop_bound, int):
            simgr.use_technique(angr.exploration_techniques.LocalLoopSeer(bound=loop_bound))

        sess_exploration = self._session_exploration(cache_intermediate_info=cache_intermediate_info)
        sess_exploration.explore(simgr)
        return self._run_result(simgr, sess_exploration)