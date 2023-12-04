import sys
from collections.abc import Callable

import portion as P

import angr, claripy
from angr import SimStateError, SimState
from angr.sim_manager import ErrorRecord
from cle import Backend

from .directive import Directive, Assume, Assert, VirtualPrint, ErrorDirective
from .terminal_state import TerminalState, AssertFailedState, ErrorState, DeadendedState

class RunResult:
    """
    This class is used for storing the results of running a session.

    :ivar list[DeadendedState] deadended: States that reached normal termination.
    :ivar list[ErrorState] errored: States that reached an error state. This may be triggered for example by program errors such as division by 0, or by reaching a :py:class:`cozy.directive.ErrorDirective`.
    :ivar list[AssertFailed] asserts_failed: States where an assertion was able to be falsified.
    :ivar list[tuple[Assume, SimState]] assume_warnings: An assume warning occurs when a :py:class:`~cozy.directive.Assume` is reached, and the added assumption contradicts the constraints for that state. This means that due to the assumption, the new constraints are not satisfiable.
    """
    def __init__(self, deadended: list[DeadendedState], errored: list[ErrorState], asserts_failed: list[AssertFailedState], assume_warnings: list[tuple[Assume, SimState]]):
        self.deadended = deadended
        self.errored = errored
        self.asserts_failed = asserts_failed
        self.assume_warnings = assume_warnings

    @property
    def assertion_triggered(self) -> bool:
        """
        Returns True if there were any assertions triggered during this run.

        :return: True if there were assertions triggered.
        :rtype: bool
        """
        return len(self.asserts_failed) > 0

    def __str__(self):
        return "RunResult({} deadended, {} errored, {} asserts_failed, {} assume_warnings)".format(len(self.deadended), len(self.errored), len(self.asserts_failed), len(self.assume_warnings))

    def report_errored(self, args: any, concrete_arg_mapper: Callable[[any], any] | None = None, num_examples: int = 3) -> str:
        """
        Creates a human readable report about a list of errored states.

        :param any args: The arguments to concretize
        :param Callable[[any], any] | None concrete_arg_mapper: This function is used to post-process concretized versions of args before they are added to the return string. Some examples of this function include converting an integer to a negative number due to use of two's complement, or slicing off parts of the argument based on another part of the input arguments.
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
                    if concrete_arg_mapper is not None:
                        concrete_args = concrete_arg_mapper(concrete_input.args)
                    else:
                        concrete_args = concrete_input.args
                    output += "{}.\n".format(j + 1)
                    output += "\t{}\n".format(str(concrete_args))
                output += "\n"
            return output

    def report_asserts_failed(self, args: any, concrete_arg_mapper: Callable[[any], any] | None = None, num_examples: int = 3) -> str:
        """
        Creates a human readable report about a list of failed assertions.

        :param any args: The arguments to concretize
        :param Callable[[any], any] | None concrete_arg_mapper: This function is used to post-process concretized versions of args before they are added to the return string. Some examples of this function include converting an integer to a negative number due to use of two's complement, or slicing off parts of the argument based on another part of the input arguments.
        :param int num_examples: The maximum number of concrete examples to show the user for each assertion failed state.
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
                    if concrete_arg_mapper is not None:
                        concrete_args = concrete_arg_mapper(concrete_input.args)
                    else:
                        concrete_args = concrete_input.args
                    output += "{}.\n".format(i + 1)
                    output += "\t{}\n".format(str(concrete_args))
                    if len(concrete_input.vprints) > 0:
                        output += "Virtual prints:\n"
                        for (pdirective, conc_print_val) in concrete_input.vprints:
                            if pdirective.concrete_mapper is not None:
                                conc_print_val = pdirective.concrete_mapper(conc_print_val)
                            output += "{}: {}\n".format(pdirective.info_str, conc_print_val)
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

class Session:
    """
    A session is a particular run of a project, consisting of attached directives (asserts/assumes).
    You can malloc memory for storage prior to running the session.
    Once you are ready to run the session, use the run method.

    :ivar angr.SimState state: The initial state tied to this particular session. You can access this member to modify properties of the state before a run.
    :ivar Project proj: The Project tied to this session.
    :ivar str | int | None start_fun: The starting function tied to this session. If start_fun is None, then the session starts in an entry state.
    :ivar list[Directive] directives: The directives added to this session.
    :ivar bool has_run: True if the :py:meth:`cozy.project.Session.run` method has been called, otherwise False.
    """
    def __init__(self, proj, start_fun: str | int | None=None):
        """
        Constructs a session derived from a project. The :py:meth:`cozy.project.Project.session` is the preferred method for creating a session, not this constructor.
        """
        self.proj = proj

        self.start_fun = start_fun

        state_options = {angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS, angr.options.SYMBOLIC_WRITE_ADDRESSES}

        # Create the initial state
        if start_fun is None:
            self.state = self.proj.angr_proj.factory.entry_state(add_options=state_options)
        else:
            self.state = self.proj.angr_proj.factory.blank_state(add_options=state_options)

        self.state.inspect.b('mem_write', when=angr.BP_AFTER, action=_on_mem_write)

        # Initialize mutable state related to this session
        self.directives = []
        self.has_run = False

    def store_fs(self, filename: str, simfile: angr.SimFile) -> None:
        """
        Stores a file in a virtual filesystem available during execution. This method simply forwards the arguments to state.fs.insert.

        :param str filename: The filename of the new file.
        :param angr.SimFile simfile: The file to make available to the simulated program.
        :return: None
        :rtype: None
        """
        self.state.fs.insert(filename, simfile)

    def malloc(self, num_bytes: int) -> int:
        """
        Mallocs a fixed amount of memory using the angr heap simulation plugin. Useful for setting things up in memory before the :py:meth:`~cozy.project.Project.run` method is called.

        :param int num_bytes: The number of bytes to allocate.
        :return: A pointer to the allocated memory block.
        :rtype: int
        """
        return self.state.heap._malloc(num_bytes)

    def store(self, addr: int, data: claripy.ast.bits, **kwargs):
        """
        Stores data at some address. This method simply forwards the arguments to state.memory.store.

        :param int addr: Address to store the data at.
        :param claripy.ast.bits data: The data to store in memory.
        :param kwargs: Additional keyword arguments to pass to state.memory.store
        """
        self.state.memory.store(addr, data, **kwargs)

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

    def _save_states(self, states):
        for state in states:
            # SimStateHistory already has a variable named strongref_state that is used when EFFICIENT_STATE_MERGING
            # is enabled. However strongref_state in SimStateHistory may be set to None as part of a state cleanup
            # process. It seems that the primary usecase for strongref_state in angr is to help with merging states
            state.history.custom_strongref_state = state

    def _save_constraints(self, states):
        for state in states:
            state.history.custom_constraints = state.solver.constraints

    def run(self, *args: claripy.ast.bits, cache_intermediate_states: bool=False, cache_constraints: bool=True, ret_addr: int | None=None) -> RunResult:
        """
        Runs a session to completion, either starting from the start_fun used to create the session, or from the program start. Note that currently a session may be run only once. If run is called multiple times, a RuntimeError will be thrown.

        :param claripy.ast.bits args: The arguments to pass to the function. angr will utilize the function's type signature to figure out the calling convention to use with the arguments.
        :param bool cache_intermediate_states: If this flag is True, then intermediate execution states will be cached, preventing their garbage collection. This is required for dumping the execution graph.
        :param bool cache_constraints: If this flag is True, then the intermediate execution state's constraints will be cached, which is required for performing memoized binary search when diffing states.
        :param int | None ret_addr: What address to return to if calling as a function
        :return: The result of running this session.
        :rtype: RunResult
        """

        # TODO: Figure out if we can safely remove this restriction. Initial tests seem to suggest that
        # running twice will result in different outcomes
        if self.has_run:
            raise RuntimeError("This session has already been run once. Make a new session to run again.")
        self.has_run = True

        if cache_intermediate_states:
            self._save_states([self.state])

        # Determine the address of the desired function
        if self.start_fun is None:
            fun_addr = None
        elif isinstance(self.start_fun, int):
            fun_addr = self.start_fun
        elif isinstance(self.start_fun, str):
            fun_addr = self.proj.find_symbol_addr(self.start_fun)
        else:
            raise TypeError("Type of start_fun passed to this session's constructor is incorrect")

        if fun_addr is not None:
            if self.start_fun in self.proj.fun_prototypes:
                fun_prototype = self.proj.fun_prototypes[self.start_fun]
            elif fun_addr in self.proj.fun_prototypes:
                fun_prototype = self.proj.fun_prototypes[fun_addr]
            else:
                fun_prototype = None

            kwargs = dict() if ret_addr is None else {"ret_addr": ret_addr}

            state = self.proj.angr_proj.factory.call_state(fun_addr, *args, base_state=self.state, prototype=fun_prototype, add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS, angr.options.SYMBOLIC_WRITE_ADDRESSES}, **kwargs)
        else:
            state = self.state

        if cache_intermediate_states:
            self._save_states([state])
        if cache_constraints:
            self._save_constraints([state])

        # This concretization strategy is necessary for nullable symbolic pointers. The default
        # concretization strategies attempts to concretize to integers within a small (128) byte
        # range. If that fails, it just selects the maximum possible concrete value. This strategy
        # will ensure that we generate up to 128 possible concrete values.
        concrete_strategy = angr.concretization_strategies.SimConcretizationStrategyUnlimitedRange(128)
        state.memory.read_strategies.insert(0, concrete_strategy)
        state.memory.write_strategies.insert(0, concrete_strategy)

        simgr = self.proj.angr_proj.factory.simulation_manager(state, veritesting=False)

        assume_warnings: list[tuple[Assume, SimState]] = []
        asserts_failed: list[AssertFailedState] = []

        if len(self.directives) > 0:
            addrs_to_directive = {}
            for directive in self.directives:
                if directive.addr in addrs_to_directive:
                    addrs_to_directive[directive.addr].append(directive)
                else:
                    addrs_to_directive[directive.addr] = [directive]

            find_addrs = set(addrs_to_directive.keys())

            while len(simgr.active) > 0:
                # Explore seems to check the find list BEFORE stepping
                simgr.explore(find=find_addrs, n=1)

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
                                if not found_state.satisfiable():
                                    assume_warnings.append((directive, found_state))
                                    print("cozy WARNING: Assume for address {} was not satisfiable. In this path of execution there is no possible way for execution to proceed past this point: {}".format(hex(directive.addr), str(cond)))
                                    if directive.info_str is not None:
                                        print(directive.info_str)
                            elif isinstance(directive, Assert):
                                cond = directive.condition_fun(found_state)
                                # Split execution into two states: one where the assertion holds and one where it
                                # doesn't hold
                                true_branch = found_state.copy()
                                true_branch.add_constraints(cond)
                                add_states.add(true_branch)

                                # To check for validity, we need to check that (not cond) is unsatisfiable
                                false_branch = found_state.copy()
                                false_branch.add_constraints(~cond)
                                if false_branch.satisfiable():
                                    if cache_intermediate_states:
                                        self._save_states([false_branch])
                                    if cache_constraints:
                                        self._save_constraints([false_branch])
                                    # If the false branch is satisfiable, add it to the list of failed assert states
                                    # This essentially halts execution on the false branch
                                    af = AssertFailedState(directive, cond, false_branch, len(asserts_failed))
                                    asserts_failed.append(af)
                                    # If false_branch is not satisfiable, then there is no way for the assertion to fail.
                                # In any case, we should prune out the original state
                                prune_states.add(found_state)
                            elif isinstance(directive, VirtualPrint):
                                if 'virtual_prints' in found_state.globals:
                                    accum_prints = found_state.globals['virtual_prints'].copy()
                                else:
                                    accum_prints = []
                                accum_prints.append((directive, directive.log_fun(found_state)))
                                found_state.globals['virtual_prints'] = accum_prints
                            elif isinstance(directive, ErrorDirective):
                                prune_states.add(found_state)
                                simgr.errored.append(ErrorRecord(found_state, SimStateError(directive.info_str), sys.exc_info()[2]))
                    else:
                        raise RuntimeError("One of the found states was not satisfiable. This probably shouldn't have happened.")

                # After we are done iterating over the found states, it is now safe to prune the ones that triggered
                # an error
                simgr.move(from_stash='found', to_stash='pruned', filter_func=lambda state: state in prune_states)

                for state in add_states:
                    simgr.found.append(state)

                if cache_intermediate_states:
                    self._save_states(simgr.found)
                if cache_constraints:
                    self._save_constraints(simgr.found)
                # We need to step over all the found states so that we don't immediately halt
                # execution of these states in the next interation of the loop
                simgr.step(num_inst=1, stash="found")
                simgr.move(from_stash='found', to_stash="active")
                errored_states = [error_record.state for error_record in simgr.errored]
                if cache_intermediate_states:
                    self._save_states(simgr.active)
                    self._save_states(errored_states)
                if cache_constraints:
                    self._save_constraints(simgr.active)
                    self._save_constraints(errored_states)
        else:
            while len(simgr.active) > 0:
                simgr.step()
                if cache_intermediate_states:
                    self._save_states(simgr.active)
                if cache_constraints:
                    self._save_constraints(simgr.active)

        deadended = [DeadendedState(state, i) for (i, state) in enumerate(simgr.deadended)]
        errored = [ErrorState(error_record, i) for (i, error_record) in enumerate(simgr.errored)]

        return RunResult(deadended, errored, asserts_failed, assume_warnings)

class Project:
    """
    Represents a project for a single executable

    :ivar angr.Project angr_proj: The angr project created for this cozy project.
    :ivar dict[str | int, str] fun_prototypes: Maps function names or function addresses to their type signatures.
    """

    def __init__(self, binary_path: str, fun_prototypes: dict[str | int, str] | None=None):
        """
        Constructor for a project.

        :param str binary_path: The path to the binary to analyze.
        :param dict[str | int, str] | None fun_prototypes: Initial dictionary that maps function names or addresses to their type signatures. If None is passed, fun_prototypes is initialized to the empty dictionary.
        """
        self.angr_proj = angr.Project(binary_path)
        if fun_prototypes is None:
            self.fun_prototypes = {}
        else:
            self.fun_prototypes = fun_prototypes

    def object_ranges(self, obj_filter: Callable[[Backend], bool] | None=None) -> list[range]:
        """
        Returns the ranges of the objects stored in the executable (for example: ELF objects). If obj_filter is specified, only objects that pass the filter make it into the return list.

        :param Callable[[Backend], bool] | None obj_filter: Used to filter certain objects from the output list.
        :return: A list of memory ranges.
        :rtype: list[range]
        """
        if obj_filter is None:
            obj_filter = lambda x: True
        return [range(obj.min_addr, obj.max_addr + 1) for obj in self.angr_proj.loader.all_objects if obj_filter(obj)]

    def find_symbol_addr(self, sym_name: str) -> int:
        """
        Finds the rebased addressed of a symbol. Functions are the most common symbol type.

        :param str sym_name: The symbol to lookup.
        :return: The rebased symbol address
        :rtype: int
        """
        return self.angr_proj.loader.find_symbol(sym_name).rebased_addr

    # fun can be either the address of a function or a function name
    def add_prototype(self, fun: str | int, fun_prototype: str) -> None:
        """
        Adds a function prototype to this project.

        :param str | int fun: The function's name or address.
        :param str fun_prototype: The function's type signature.
        :return: None
        :rtype: None
        """
        self.fun_prototypes[fun] = fun_prototype

    def session(self, start_fun: str | int | None=None) -> Session:
        """
        Returns a new session derived from this project.

        :param str | int | None start_fun: The name or address of the function which this session will start with. If None is specified, then the program will start at the entry point (main function).
        :return: The fresh session.
        :rtype: Session
        """
        return Session(self, start_fun=start_fun)
