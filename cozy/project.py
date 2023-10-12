import sys

import angr, claripy
from angr import SimStateError, SimState
from angr.sim_manager import ErrorRecord

from .directive import Assume, Assert, VirtualPrint, ErrorDirective

class RunResult:
    def __init__(self, assume_warnings: list[tuple[Assume, SimState]]):
        self.assume_warnings = assume_warnings

class TerminatedResult(RunResult):
    def __init__(self, deadended: list[SimState], errored: list[ErrorRecord], assume_warnings: list[tuple[Assume, SimState]]):
        super().__init__(assume_warnings)
        self.deadended = deadended
        self.errored = errored

class AssertFailed(RunResult):
    def __init__(self, assert_failed, assume_warnings: list[tuple[Assume, SimState]]):
        super().__init__(assume_warnings)
        self.assert_failed = assert_failed

# This on_mem_write is designed to be attached as a breakpoint that is triggered
# whenever memory is written. This hook simply logs the current instruction pointer
# for each written byte in state.globals['mem_writes']
def on_mem_write(state):
    # TODO: Switch from Python dictionary to purely function map/dictionary
    # data structure for better performance.
    if 'mem_writes' in state.globals:
        mem_writes = dict(state.globals['mem_writes'])
    else:
        mem_writes = dict()
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
            for addr in range(st_addr, st_addr + length):
                if len(start_addrs) > 1 and addr in mem_writes:
                    mem_writes[addr] = mem_writes[addr].union(ip_frozenset)
                else:
                    mem_writes[addr] = ip_frozenset
    state.globals['mem_writes'] = mem_writes

# A session is a particular run of a project, consisting of attached directives
# (asserts/assumes). You can malloc memory for storage prior to running the session.
# Once you are ready to run the session, use the run method.
class Session:
    def __init__(self, proj, start_fun=None):
        self.proj = proj

        self.start_fun = start_fun

        state_options = {angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS, angr.options.SYMBOLIC_WRITE_ADDRESSES}

        # Create the initial state
        if start_fun is None:
            self.state = self.proj.angr_proj.factory.entry_state(add_options=state_options)
        else:
            self.state = self.proj.angr_proj.factory.blank_state(add_options=state_options)

        self.state.inspect.b('mem_write', when=angr.BP_AFTER, action=on_mem_write)

        # Initialize mutable state related to this session
        self.directives = []
        self.heap_registered = False
        self.has_run = False

        self.state_strong_refs = []

    def store_fs(self, filename, simfile):
        self.state.fs.insert(filename, simfile)

    def malloc(self, num_bytes):
        if not self.heap_registered:
            self.state.register_plugin("heap", angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc())
            self.heap_registered = True
        return self.state.heap.malloc(num_bytes)

    def store(self, addr, data):
        self.state.memory.store(addr, data)

    def add_directives(self, *args):
        self.directives.extend(args)

    def add_constraints(self, *args):
        self.state.add_constraints(*args)

    def save_states(self, states):
        for state in states:
            # SimStateHistory already has a variable named strongref_state that is used when EFFICIENT_STATE_MERGING
            # is enabled. However strongref_state in SimStateHistory may be set to None as part of a state cleanup
            # process. It seems that the primary usecase for strongref_state in angr is to help with merging states
            state.history.custom_strongref_state = state

    def save_constraints(self, states):
        for state in states:
            state.history.custom_constraints = state.solver.constraints

    # If start_fun is None, then we run the analysis from the program start (ie, main function)
    # start_fun can be an address of a function or a function name
    # cache_intermediate_states is required for dumping the execution graph
    # cache_constraints is required for performing memoized binary search when diffing states
    def run(self, *args, cache_intermediate_states=False, cache_constraints=True) -> AssertFailed | TerminatedResult:
        # TODO: Figure out if we can safely remove this restriction. Initial tests seem to suggest that
        # running twice will result in different outcomes
        if self.has_run:
            raise RuntimeError("This session has already been run once. Make a new session to run again.")
        self.has_run = True

        if cache_intermediate_states:
            self.save_states([self.state])

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

            state = self.proj.angr_proj.factory.call_state(fun_addr, *args, base_state=self.state, prototype=fun_prototype, add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS, angr.options.SYMBOLIC_WRITE_ADDRESSES})
        else:
            state = self.state

        if cache_intermediate_states:
            self.save_states([state])
        if cache_constraints:
            self.save_constraints([state])

        # This concretization strategy is necessary for nullable symbolic pointers. The default
        # concretization strategies attempts to concretize to integers within a small (128) byte
        # range. If that fails, it just selects the maximum possible concrete value. This strategy
        # will ensure that we generate up to 128 possible concrete values.
        concrete_strategy = angr.concretization_strategies.SimConcretizationStrategyUnlimitedRange(128)
        state.memory.read_strategies.insert(0, concrete_strategy)
        state.memory.write_strategies.insert(0, concrete_strategy)

        simgr = self.proj.angr_proj.factory.simulation_manager(state, veritesting=False)

        assume_warnings: list[tuple[Assume, SimState]] = []

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

                for found_state in simgr.found:
                    if found_state.satisfiable():
                        relevant_directives = addrs_to_directive[found_state.addr]
                        if len(relevant_directives) == 0:
                            print("Gotcha")
                        for directive in relevant_directives:
                            if isinstance(directive, Assume):
                                cond = directive.condition_fun(found_state)
                                found_state.add_constraints(cond)
                                print("Checking Assume...")
                                if not found_state.satisfiable():
                                    assume_warnings.append((directive, found_state))
                                    print("Assume for address {} was not satisfiable. In this path of execution there is no possible way for execution to proceed past this point: {}".format(hex(directive.addr), str(cond)))
                                    if directive.info_str is not None:
                                        print(directive.info_str)
                            elif isinstance(directive, Assert):
                                cond = directive.condition_fun(found_state)
                                # To check for validity, we need to check that (not cond) is unsatisfiable
                                state_cpy = found_state.copy()
                                state_cpy.add_constraints(~cond)
                                print("Checking Assert...")
                                if state_cpy.satisfiable():
                                    print("Assert for address {} was triggered: {}".format(hex(directive.addr), str(cond)))
                                    if directive.info_str is not None:
                                        print(directive.info_str)
                                    return AssertFailed(directive, assume_warnings)
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

                if cache_intermediate_states:
                    self.save_states(simgr.found)
                if cache_constraints:
                    self.save_constraints(simgr.found)
                # We need to step over all the found states so that we don't immediately halt
                # execution of these states in the next interation of the loop
                simgr.step(num_inst=1, stash="found")
                simgr.move(from_stash='found', to_stash="active")
                errored_states = [error_record.state for error_record in simgr.errored]
                if cache_intermediate_states:
                    self.save_states(simgr.active)
                    self.save_states(errored_states)
                if cache_constraints:
                    self.save_constraints(simgr.active)
                    self.save_constraints(errored_states)

            print("No asserts triggered!")
        else:
            while len(simgr.active) > 0:
                simgr.step()
                if cache_intermediate_states:
                    self.save_states(simgr.active)
                if cache_constraints:
                    self.save_constraints(simgr.active)

        return TerminatedResult(simgr.deadended, simgr.errored, assume_warnings)

class Project:
    # fun_prototypes should be a dictionary mapping function names/and or addresses
    # to prototypes (type signatures) of the functions
    def __init__(self, binary_path, fun_prototypes=None):
        self.angr_proj = angr.Project(binary_path)
        if fun_prototypes is None:
            self.fun_prototypes = {}
        else:
            self.fun_prototypes = fun_prototypes

    def object_ranges(self, obj_filter=lambda x: True):
        return [range(obj.min_addr, obj.max_addr + 1) for obj in self.angr_proj.loader.all_objects if obj_filter(obj)]

    def find_symbol_addr(self, fun_name):
        return self.angr_proj.loader.find_symbol(fun_name).rebased_addr

    # fun can be either the address of a function or a function name
    def add_prototype(self, fun, fun_prototype):
        self.fun_prototypes[fun] = fun_prototype

    def session(self, start_fun=None):
        return Session(self, start_fun=start_fun)
