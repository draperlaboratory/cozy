from collections.abc import Iterator

import claripy
from angr import SimState
from enum import Enum

import portion as P

from angr.sim_manager import ErrorRecord
from angr.state_plugins import SimStateHistory
from . import claripy_ext
from . import directive
from . import functools_ext
from .functools_ext import *
from . import range_ext
import sys
import collections.abc
from .project import RunResult, AssertFailed


class StateTag(Enum):
    TERMINATED_STATE = 0
    ERROR_STATE = 1
    ASSERT_FAILED_STATE = 2

# Given a state, returns a range of addresses that were used as part of the stack but are no longer
# valid stack locations. This will happen if the stack grows, then shrinks.
def _invalid_stack_addrs(st: SimState) -> range:
    curr_sp = st.callstack.stack_ptr
    # The red page is at the extrema of the stack, so we can use that to determine
    # the addresses to diqualify
    red_page_addr = st.memory._red_pageno * st.memory.page_size
    if st.arch.stack_change < 0:
        # The stack grows down
        return range(red_page_addr, curr_sp)
    else:
        # The stack grows up
        return range(curr_sp + 1, red_page_addr + st.memory.page_size)

# If stack_change is negative, then the stack grows down
# Otherwise the stack grows up
def _invalid_stack_overlap(invalid_stack_left: range, invalid_stack_right: range, stack_change: int):
    if stack_change < 0:
        start = min(invalid_stack_left.start, invalid_stack_right.start)
        stop = min(invalid_stack_left.stop, invalid_stack_right.stop)
    else:
        start = max(invalid_stack_left.start, invalid_stack_right.start)
        stop = max(invalid_stack_left.stop, invalid_stack_right.stop)
    return range(start, stop)

class StateDiff:
    """
    StateDiff encapsulates the memoized state used by the difference method. This class is used internally by Comparison and is typically not for external use.
    """

    def __init__(self, use_memoized_binary_search=True):
        """
        :param bool use_memoized_binary_search: When use_memoized_binary_search is enabled, the difference algorithm will begin by comparing ancestors of the left and right states rather than the states themselves. This will improve performance in most cases, but will actually degrade performance when all pairs of states are compatible. This is because early exits from difference occur when ancestor states are incompatible.
        """
        self._compatible: set[tuple[SimStateHistory, SimStateHistory]] = set()
        self._incompatible: set[tuple[SimStateHistory, SimStateHistory]] = set()
        self.use_memoized_binary_search = use_memoized_binary_search

    def difference(self,
                   sl: SimState, sr: SimState,
                   ignore_addrs: collections.abc.Iterable[range] | None = None,
                   compute_mem_diff=True,
                   compute_reg_diff=True) -> (
            tuple[dict[range, tuple[claripy.ast.bits, claripy.ast.bits]], dict[str, tuple[claripy.ast.bits, claripy.ast.bits]]] | None):
        """
        Compares two states to find differences in memory. This function will return None if the two states have non-intersecting inputs. Otherwise, it will return a dict of addresses and a dict of registers which are different between the two. This function is based off of angr.analyses.congruency_check.CongruencyCheck().compare_states, but has been customized for our purposes. Note that this function may use memoization to enhance performance.

        :param SimState sl: The first state to compare
        :param SimState sr: The second state to compare
        :param collections.abc.Iterable[range] | None ignore_addrs: Memory addresses to ignore when doing the memory diffing. This representation is more efficient than a set of integers since the ranges involved can be quite large.
        :param bool compute_mem_diff: If this flag is True, then we will diff the memory. If this is false, then the first element of the return tuple will be None.
        :param compute_reg_diff: If this flag is True, then we will diff the registers. If this is false, then the second element of the return tuple will be None.
        :return: None if the two states are not compatible, otherwise returns a tuple containing the memory and register differences.
        :rtype: tuple[dict[range, tuple[claripy.ast.bits, claripy.ast.bits]], dict[str, tuple[claripy.ast.bits, claripy.ast.bits]]] | None
        """

        if self.use_memoized_binary_search:
            if (sl.history, sr.history) in self._incompatible:
                return None

            # Begin a binary search to determine at what point two states become incompatible.
            hist_left = list(sl.history.lineage)
            hist_right = list(sr.history.lineage)

            def mark_compatible(idx_left, idx_right):
                sub_hist_left = hist_left[:(idx_left + 1)]
                sub_hist_right = hist_right[:(idx_right + 1)]
                for hl in sub_hist_left:
                    for hr in sub_hist_right:
                        self._compatible.add((hl, hr))

            def mark_incompatible(idx_left, idx_right):
                sub_hist_left = hist_left[idx_left:]
                sub_hist_right = hist_right[idx_right:]
                for hl in sub_hist_left:
                    for hr in sub_hist_right:
                        self._incompatible.add((hl, hr))

            low_left = 0
            high_left = len(hist_left) - 1
            mid_left = 0
            low_right = 0
            high_right = len(hist_right) - 1
            mid_right = 0

            while mid_left < (len(hist_left) - 1) or mid_right < (len(hist_right) - 1):
                mid_left = (high_left + low_left + 1) // 2
                mid_right = (high_right + low_right + 1) // 2

                if (hist_left[mid_left], hist_right[mid_right]) in self._incompatible:
                    return None
                elif (hist_left[mid_left], hist_right[mid_right]) in self._compatible:
                    low_left = mid_left
                    low_right = mid_right
                else:
                    joint_solver = claripy.Solver()
                    joint_solver.add(hist_left[mid_left].custom_constraints)
                    joint_solver.add(hist_right[mid_right].custom_constraints)
                    joint_solver.simplify()

                    if joint_solver.satisfiable():
                        mark_compatible(mid_left, mid_right)
                        low_left = mid_left
                        low_right = mid_right
                    else:
                        mark_incompatible(mid_left, mid_right)
                        return None
        else:
            hist_left = []
            hist_right = []
            def mark_compatible(idx_left, idx_right):
                return None
            def mark_incompatible(idx_left, idx_right):
                return None

        # The reason we are adding constraints from both states is that we
        # want to get a joint system that constrains the input arguments
        # angr may generate additional internal constraints as the function is symbolically executed
        # these generated symbols will be fresh. In contrast, the input arguments
        # will be the same symbol for both functions
        joint_solver = claripy.Solver()
        joint_solver.add(sl.solver.constraints)
        joint_solver.add(sr.solver.constraints)
        # Note: Code profiling has revealed that not using simplify
        # actually leads to a longer runtime
        joint_solver.simplify()

        # If joint_solver is not satisfiable, that means that the constrained set of possible
        # inputs to the function is the empty set. This means that these two states could not
        # have been reached with a given input, and we can therefore disregard this comparison
        if not (joint_solver.satisfiable()):
            mark_incompatible(len(hist_left) - 1, len(hist_right) - 1)
            return None

        mark_compatible(len(hist_left) - 1, len(hist_right) - 1)

        ret_mem_diff = dict()

        if compute_mem_diff:
            # This is the old version of computing memory difference,
            # which loops through the allocated pages and compares the bytes.
            # This is less efficient than the new method, which uses the mem_writes
            # data saved by the on_mem_write hook. If there are problems with memory
            # that is different but is not being reported, then the first course
            # of action should be to uncomment these lines and check for differences
            #diff_addrs_old: set[int] = sl.memory.changed_bytes(sr.memory)
            #diff_addrs_old.update(sr.memory.changed_bytes(sl.memory))
            #if ignore_addrs is not None:
            #    range_ext.remove_range_list(diff_addrs_old, ignore_addrs)

            left_mem_writes = sl.globals['mem_writes']
            right_mem_writes = sl.globals['mem_writes']

            # Note that diffs does not necessarily contain the addresses of the program data itself,
            # which is what we would expect. Testing with angr showed that the page(s) containing the
            # program data are loaded lazily, in that they are not stored unless actually used
            # ex: state.memory.load(fun_addr, 1)
            # In any case it is probably a good idea to remove any patched addresses just in case
            # the state's memory actually contains them

            # Here we remove the requested intervals from the interval dictionaries
            if ignore_addrs is not None:
                left_mem_writes = left_mem_writes.copy()
                right_mem_writes = right_mem_writes.copy()
                for rng in ignore_addrs:
                    del left_mem_writes[P.closedopen(rng.start, rng.stop)]
                    del right_mem_writes[P.closedopen(rng.start, rng.stop)]

            diff_addr_ranges = {range(interval.lower, interval.upper) for interval in left_mem_writes.keys()}
            diff_addr_ranges.update({range(interval.lower, interval.upper) for interval in right_mem_writes.keys()})

            # Loop over all the address that could possibly be different and save the ones that are actually different
            for addr_range in diff_addr_ranges:
                bytes_left = sl.memory.load(addr_range.start, len(addr_range))
                bytes_right = sr.memory.load(addr_range.start, len(addr_range))
                if bytes_left is not bytes_right:
                    if joint_solver.satisfiable(extra_constraints=[bytes_left != bytes_right]):
                        # It is possible that there is a symbolic value stored in memory.
                        # Here we want to simplify this with respect to the joint constraints
                        simpl_bytes_left = claripy_ext.simplify_kb(bytes_left, joint_solver.constraints)
                        simpl_bytes_right = claripy_ext.simplify_kb(bytes_right, joint_solver.constraints)
                        ret_mem_diff[addr_range] = (simpl_bytes_left, simpl_bytes_right)

        # Loop over all the registers that could possibly be different and save the ones that are actually different
        ret_reg_diff = dict()

        if compute_reg_diff:
            for reg_name in dir(sl.regs):
                # Ignore registers that start with underscore and cc pseudoregisters (which appear to be a part of the VEX
                # framework used by angr)
                if reg_name.startswith("_") or reg_name.startswith("cc_"):
                    continue

                reg_left = getattr(sl.regs, reg_name)
                reg_right = getattr(sr.regs, reg_name)

                if reg_left is not reg_right:
                    if joint_solver.satisfiable(extra_constraints=[reg_left != reg_right]):
                        simpl_reg_left = claripy_ext.simplify_kb(reg_left, joint_solver.constraints)
                        simpl_reg_right = claripy_ext.simplify_kb(reg_right, joint_solver.constraints)
                        ret_reg_diff[reg_name] = (simpl_reg_left, simpl_reg_right)

        return (ret_mem_diff, ret_reg_diff)

def hexify(val0):
    """
    Recursively transforms all integers in a Python datastructure (that is mappable with functools_ext.fmap) to hex strings.

    :param val0: The datastructure to traverse.
    :return: A deep copy of the datastructure, with all integers converted to hex strings.
    """
    def f(val1):
        if isinstance(val1, int):
            return hex(val1)
        else:
            return val1
    return fmap(val0, f)

def _concretize(solver, state_bundle, n=1):
    def f(elem, accum):
        if isinstance(elem, claripy.ast.Base):
            accum.append(elem)
        return accum
    # eval_lst will be a list, where the order of the elements is determined by
    # the order they are visited in a preorder traversal of the Python datastructures
    # The elements in question are claripy AST nodes that we are going to evaluate
    eval_lst = preorder_fold(state_bundle, f, [])

    concrete_vals_lst = solver.batch_eval(eval_lst, n)

    ret = []

    for concrete_vals in concrete_vals_lst:
        def g(elem0, idx0):
            if isinstance(elem0, claripy.ast.Base):
                # Lookup what this AST was concretely evaluated to by indexing into
                # this list via the preorder traversal number
                elem1 = concrete_vals[idx0]
                idx1 = idx0 + 1
            else:
                elem1 = elem0
                idx1 = idx0
            return (elem1, idx1)

        (concrete_vals_prime, last_idx) = preorder_mapfold(state_bundle, g, 0)

        ret.append(concrete_vals_prime)

    return ret

def _get_virtual_prints(st):
    if 'virtual_prints' in st.globals:
        return st.globals['virtual_prints']
    else:
        return []

class ConcretePairInput:
    """
    Stores information about the concretization of a compatible state pair.

    :ivar any args: The same Python datastructures as the arguments passed to concrete_examples, except that all claripy symbolic variables are replaced with concrete values.
    :ivar dict[int, tuple[int, int]] mem_diff: Concretized version of memory difference. Each key is a memory address, and each value is a concretized version of the data stored at that location for the prepatched, postpatched runs.
    :ivar dict[str, tuple[int, int]] reg_diff: Concretized version of register difference. Each key is a register name, and each value is a concretized version of the data stored at that register for the prepatched, postpatched runs.
    :ivar list[tuple[directive.VirtualPrint, any]] left_vprints: Concretized versions of virtual prints made by the prepatched state.
    :ivar list[tuple[directive.VirtualPrint, any]] right_vprints: Concretized versions of virtual prints made by the postpatched state.
    """

    def __init__(self, args, mem_diff: dict[int, tuple[int, int]], reg_diff: dict[str, tuple[int, int]],
                 left_vprints: list[tuple[directive.VirtualPrint, any]], right_vprints: list[tuple[directive.VirtualPrint, any]]):
        self.args = args
        self.mem_diff = mem_diff
        self.reg_diff = reg_diff
        self.left_vprints = left_vprints
        self.right_vprints = right_vprints

class ConcreteSingletonInput:
    """
    Stores information about the concretization of a SingletonState.

    :ivar any args: The same Python datastructures as the arguments passed to concrete_examples, except that all claripy symbolic variables are replaced with concrete values.
    :ivar list[tuple[directive.VirtualPrint, any]] vprints: Concretized virtual prints outputted by the singleton state.
    """
    def __init__(self, args, vprints: list[tuple[directive.VirtualPrint, any]]):
        self.args = args
        self.vprints = vprints

class SingletonState:
    """
    Stores information pertaining specifically to a single SimState.

    :ivar SimState state: The state we are storing information about.
    :ivar bytes | None std_out: The data that has been written to stdout when the program is in this state. This may be None if we are ignoring stdout.
    :ivar bytes | None std_err: The data that has been written to stderr when the program is in this state. This may be None if we are ignoring stderr.
    :ivar int state_id: The index of this particular state in the corresponding list in TerminatedResult. Note that errored states have separate state_ids from deadended states. Therefore a particular input state here is uniquely identified by the pair (state_id, state_tag), not just state_id by itself.
    :ivar StateTag state_tag: Determines whether this state was an errored state or a deadended state.
    :ivar str | None error_info: Human readable string giving the error message, only used when state is an errored state.
    """

    def __init__(self, state: SimState, std_out: bytes | None, std_err: bytes | None, state_id: int, state_tag: StateTag, error_info: str | None = None):
        self.state = state
        self.state_id = state_id
        self.state_tag = state_tag
        self.std_out = std_out
        self.std_err = std_err
        self.error_info = error_info

    def concrete_examples(self, args: any, num_examples=3) -> list[ConcreteSingletonInput]:
        """
        Concretizes the arguments used to put the program in this singleton state.

        :param any args: The input arguments to concretize. This argument may be a Python datastructure, the concretizer will make a deep copy with claripy symbolic variables replaced with concrete values.
        :param int num_examples: The maximum number of concrete examples to generate for this singleton state.
        :return: A list of concrete inputs that satisfies the constraints attached to the state.
        :rtype: list[ConcreteSingletonInput]
        """
        state_bundle = (args, _get_virtual_prints(self.state))
        solver = claripy.Solver()
        solver.add(self.state.solver.constraints)
        # self.state.solver does not seem to support the batch_eval method, so we can't use that here
        concrete_results = _concretize(solver, state_bundle, n=num_examples)
        return [ConcreteSingletonInput(conc_args, conc_vprints) for (conc_args, conc_vprints) in concrete_results]

class PairComparison:
    """
    Stores information about comparing two compatible states.

    :ivar SingletonState state_left: Information pertaining specifically to the pre-patched state being compared.
    :ivar SingletonState state_right: Information pertaining specificially to the post-patched state being compared.
    :ivar dict[range, tuple[claripy.ast.Base, claripy.ast.Base]] mem_diff: Maps memory addresses to pairs of claripy ASTs, where the left element of the tuple is the data in memory for state_left, and the right element of the tuple is what was found in memory for state_right. Only memory locations that are different are saved in this dict.
    :ivar dict[str, tuple[claripy.ast.Base, claripy.ast.Base]] reg_diff: Similar to mem_diff, except that the dict is keyed by register names. Note that some registers may be subparts of another. For example in x64, EAX is a subregister of RAX.
    :ivar dict[int, tuple[frozenset[claripy.ast.Base]], frozenset[claripy.ast.Base]] mem_diff_ip: Maps memory addresses to a set of instruction pointers that the program was at when it wrote that byte in memory. In most cases the frozensets will have a single element, but this may not be the case in the scenario where a symbolic value determined the write address.
    """

    def __init__(self,
                 state_left: SingletonState,
                 state_right: SingletonState,
                 mem_diff: dict[range, tuple[claripy.ast.Base, claripy.ast.Base]],
                 # TODO: Expose the subregister structure somewhere
                 reg_diff: dict[str, tuple[claripy.ast.Base, claripy.ast.Base]],
                 mem_diff_ip: dict[int, tuple[frozenset[claripy.ast.Base]], frozenset[claripy.ast.Base]]):
        self.state_left = state_left
        self.state_right = state_right
        self.mem_diff = mem_diff
        self.reg_diff = reg_diff
        self.mem_diff_ip = mem_diff_ip

    def equal(self) -> bool:
        """
        Determines if the two compatible states are observationally equal. That is, they contain the same memory contents, registers, stdout, and stderr after execution.

        :return: True if the two compatible states are observationally equal, and False otherwise.
        :rtype: bool
        """
        return (len(self.mem_diff) == 0 and len(self.reg_diff) == 0 and
                (self.state_left.std_out is None or self.state_right.std_out is None or (self.state_left.std_out == self.state_right.std_out)) and
                (self.state_left.std_err is None or self.state_right.std_err is None or (self.state_left.std_err == self.state_right.std_err)))

    def concrete_examples(self, args: any, num_examples=3) -> list[ConcretePairInput]:
        """
        Concretizes the arguments used to put the program in these states by jointly using the constraints attached to the compatible states.

        :param any args: The input arguments to concretize. This argument may be a Python datastructure, the concretizer will make a deep copy with claripy symbolic variables replaced with concrete values.
        :param int num_examples: The maximum number of concrete examples to generate for this particular pair.
        :return: A list of concrete inputs that satisfy both constraints attached to the states.
        :rtype: list[ConcretePairInput]
        """
        sl = self.state_left.state
        sr = self.state_right.state
        joint_solver = claripy.Solver()
        joint_solver.add(sl.solver.constraints)
        joint_solver.add(sr.solver.constraints)
        state_bundle = (args, self.mem_diff, self.reg_diff, _get_virtual_prints(sl), _get_virtual_prints(sr))
        concrete_results = _concretize(joint_solver, state_bundle, n=num_examples)
        return [ConcretePairInput(conc_args, conc_mem_diff, conc_reg_diff, conc_vprints_left, conc_vprints_right)
                for (conc_args, conc_mem_diff, conc_reg_diff, conc_vprints_left, conc_vprints_right) in
                concrete_results]

class Comparison:
    """
    This class stores all compatible pairs and orphaned states. An orphan state is one in which there is no compatible state in the other execution tree. In most scenarios there will be no orphaned states.

    :ivar dict[tuple[SimState, SimState], PairComparison] pairs: pairs stores a dictionary that maps a pair of (pre_patch_state, post_patch_state) compatible states to their comparison information
    :ivar dict[SimState, SingletonState] orphans_left_lookup: maps pre-patched orphaned states to singleton state information
    :ivar dict[SimState, SingletonState] orphans_right_lookup: maps post-patched orphaned states to singleton state information
    """

    def __init__(self, pre_patched: RunResult, post_patched: RunResult, ignore_addrs: list[range] | None = None,
                 ignore_invalid_stack=True, compare_memory=True, compare_registers=True, compare_std_out=False,
                 compare_std_err=False, use_memoized_binary_search=True):
        """
        Compares a bundle of pre-patched states with a bundle of post-patched states.

        :param project.RunResult pre_patched: The pre-patched state bundle
        :param project.RunResult post_patched: The post-patched state bundle
        :param list[range] | None ignore_addrs: A list of addresses ranges to ignore when comparing memory.
        :param bool ignore_invalid_stack: If this flag is True, then memory differences in locations previously occupied by the stack are ignored.
        :param bool compare_memory: If True, then the analysis will compare locations in the program memory.
        :param bool compare_registers: If True, then the analysis will compare registers used by the program.
        :param bool compare_std_out: If True, then the analysis will save stdout written by the program in the results. Note that angr currently concretizes values written to stdout, so these values will be binary strings.
        :param bool compare_std_err: If True, then the analysis will save stderr written by the program in the results.
        :param bool use_memoized_binary_search: If True, then when the analysis compares sets of states it will first try to compare ancestor states in a binary search strategy. For most programs this will speed up comparison. For programs where all states are compatible, expect a slowdown.
        """

        if ignore_addrs is None:
            ignore_addrs = []

        self.pairs: dict[tuple[SimState, SimState], PairComparison] = dict()
        # An orphan is a state that is not compatible with any other state
        # Testing has revealed that there are typically never any orphans
        self.orphans_left_lookup: dict[SimState, SingletonState] = dict()
        self.orphans_right_lookup: dict[SimState, SingletonState] = dict()

        singleton_state_cache: dict[SimState, SingletonState] = dict()
        def get_singleton_state(state_info: SimState | ErrorRecord | AssertFailed, state_id: int) -> SingletonState:
            if isinstance(state_info, ErrorRecord):
                error_info = state_info.error
                state: SimState = state_info.state
                state_tag = StateTag.ERROR_STATE
            elif isinstance(state_info, AssertFailed):
                error_info = state_info.assertion.info_str
                state: SimState = state_info.failure_state
                state_tag = StateTag.ASSERT_FAILED_STATE
            else:
                error_info = None
                state: SimState = state_info
                state_tag = StateTag.TERMINATED_STATE

            if state in singleton_state_cache:
                return singleton_state_cache[state]
            else:
                if compare_std_out:
                    stdout_fileno = sys.stdout.fileno()
                    stdout = state.posix.dumps(stdout_fileno)
                else:
                    stdout = None
                if compare_std_err:
                    stderr_fileno = sys.stderr.fileno()
                    stderr = state.posix.dumps(stderr_fileno)
                else:
                    stderr = None
                sing_state = SingletonState(state, stdout, stderr, state_id, state_tag, error_info)
                singleton_state_cache[state] = sing_state
                return sing_state

        memoized_diff = StateDiff(use_memoized_binary_search=use_memoized_binary_search)

        def compare(states_pre_patched: list[SimState] | list[ErrorRecord] | list[AssertFailed],
                    states_post_patched: list[SimState] | list[ErrorRecord] | list[AssertFailed],
                    orphans_pre: dict[int, SimState] | dict[int, ErrorRecord] | dict[int, AssertFailed],
                    orphans_post: dict[int, SimState] | dict[int, ErrorRecord] | dict[int, AssertFailed]):
            def unwrap_sim_state(state_info: SimState | ErrorRecord | AssertFailed) -> SimState:
                if isinstance(state_info, ErrorRecord):
                    return state_info.state
                elif isinstance(state_info, AssertFailed):
                    return state_info.failure_state
                else:
                    return state_info

            # If ignore_invalid_stack is enabled, then any data that was stored on the stack in the past,
            # but is now invalid due to movement of the stack pointer is ignored
            if ignore_invalid_stack:
                inv_addrs_pre_patched = list(
                    map(functools_ext.compose(_invalid_stack_addrs, unwrap_sim_state), states_pre_patched))
                inv_addrs_post_patched = list(
                    map(functools_ext.compose(_invalid_stack_addrs, unwrap_sim_state), states_post_patched))
            else:
                inv_addrs_pre_patched = None
                inv_addrs_post_patched = None

            is_terminated_comparison = True

            for (i, state_pre_info) in enumerate(states_pre_patched):
                state_pre = unwrap_sim_state(state_pre_info)
                if isinstance(state_pre_info, ErrorRecord) or isinstance(state_pre_info, AssertFailed):
                    is_terminated_comparison = False
                for (j, state_post_info) in enumerate(states_post_patched):
                    state_post: SimState = unwrap_sim_state(state_post_info)
                    if isinstance(state_post_info, ErrorRecord) or isinstance(state_post_info, AssertFailed):
                        is_terminated_comparison = False

                    if ignore_invalid_stack:
                        stack_change = state_pre.arch.stack_change
                        pair_ignore_addrs = ignore_addrs + [_invalid_stack_overlap(inv_addrs_pre_patched[i], inv_addrs_post_patched[j], stack_change)]
                    else:
                        pair_ignore_addrs = ignore_addrs

                    diff = memoized_diff.difference(
                        state_pre, state_post, pair_ignore_addrs,
                        compute_mem_diff=compare_memory if is_terminated_comparison else False,
                        compute_reg_diff=compare_registers if is_terminated_comparison else False
                    )

                    if diff is not None:
                        # These states are compatible, so remove them from the orphans dict
                        orphans_pre.pop(i, None)
                        orphans_post.pop(j, None)

                        (mem_diff, reg_diff) = diff

                        def get_ip_set(interval_dict, r: range):
                            # Query the interval dictionary for all entries in the desired range, then union
                            # all of those sets together
                            ip_sets = [s for (n, s) in interval_dict[P.closedopen(r.start, r.stop)].values()]
                            return frozenset().union(*ip_sets)

                        mem_diff_ip = {
                            addr_range:
                                (get_ip_set(state_pre.globals['mem_writes'], addr_range),
                                 get_ip_set(state_post.globals['mem_writes'], addr_range))
                            for addr_range in mem_diff.keys()
                        }

                        comparison = PairComparison(
                            get_singleton_state(state_pre_info, i),
                            get_singleton_state(state_post_info, j),
                            mem_diff, reg_diff, mem_diff_ip
                        )

                        self._add_pair(comparison)

        orphans_pre: dict[int, SimState] = dict(enumerate(pre_patched.deadended))
        orphans_post: dict[int, SimState] = dict(enumerate(post_patched.deadended))
        orphans_pre_errored: dict[int, ErrorRecord] = dict(enumerate(pre_patched.errored))
        orphans_post_errored: dict[int, ErrorRecord] = dict(enumerate(post_patched.errored))
        orphans_pre_assert: dict[int, AssertFailed] = dict(enumerate(pre_patched.asserts_failed))
        orphans_post_assert : dict[int, AssertFailed] = dict(enumerate(post_patched.asserts_failed))

        state_bundles_pre = [
            (pre_patched.deadended, orphans_pre),
            (pre_patched.errored, orphans_pre_errored),
            (pre_patched.asserts_failed, orphans_pre_assert)
        ]

        state_bundles_post = [
            (post_patched.deadended, orphans_post),
            (post_patched.errored, orphans_post_errored),
            (post_patched.asserts_failed, orphans_post_assert)
        ]

        for (pre_patched_states, pre_orphans_dict) in state_bundles_pre:
            for (post_patched_states, post_orphans_dict) in state_bundles_post:
                compare(pre_patched_states, post_patched_states, pre_orphans_dict, post_orphans_dict)

        def add_orphans(orphans_dict: dict[int, SimState] | dict[int, ErrorRecord] | dict[int, AssertFailed], add_orphan):
            # These states that are orphans did not have any compatible states
            for (i, orphan_state) in orphans_dict.items():
                add_orphan(get_singleton_state(orphan_state, i))

        add_orphans(orphans_pre, self._add_orphan_left)
        add_orphans(orphans_post, self._add_orphan_right)
        add_orphans(orphans_pre_errored, self._add_orphan_left)
        add_orphans(orphans_post_errored, self._add_orphan_right)
        add_orphans(orphans_pre_assert, self._add_orphan_left)
        add_orphans(orphans_post_assert, self._add_orphan_right)

    def _add_pair(self, pair_comp: PairComparison):
        """
        Adds a result of comparing two states to the result object.

        :param pair_comp: The comparison to add
        :return: None
        """
        self.pairs[(pair_comp.state_left.state, pair_comp.state_right.state)] = pair_comp

    def _add_orphan_left(self, orph_state: SingletonState):
        """
        Adds a pre-patched orphan to the result object.

        :param orph_state: The orphaned state to add
        :return: None
        """
        self.orphans_left_lookup[orph_state.state] = orph_state

    def _add_orphan_right(self, orph_state: SingletonState):
        """
        Adds a post-patched orphan to the result object.

        :param orph_state: The orphaned state to add
        :return: None
        """
        self.orphans_right_lookup[orph_state.state] = orph_state

    def get_comparison(self, state_left: SimState, state_right: SimState) -> PairComparison:
        """
        Retrieves a PairComparison given two compatible input states.

        :param SimState state_left: The pre-patched state
        :param SimState state_right: The post-patched state
        :return: The PairComparison object corresponding to this compatible state pair.
        :rtype: PairComparison
        """
        return self.pairs[(state_left, state_right)]

    def get_orphan_left(self, state: SimState) -> SingletonState:
        """
        Gets the SingletonState for the input pre-patched orphan state.

        :param SimState state: A pre-patched orphan state
        :return: Information about the execution of the pre-patched orphan
        :rtype: SingletonState
        """
        return self.orphans_left_lookup[state]

    def get_orphan_right(self, state: SimState) -> SingletonState:
        """
        Gets the SingletonState for the input post-patched orphan state.

        :param SimState state: A post-patched orphan state
        :return: Information about the execution of the post-patched orphan
        :rtype: SingletonState
        """
        return self.orphans_right_lookup[state]

    def orphans_left(self) -> Iterator[SingletonState]:
        """
        Iterates over pre-patched orphans

        :return: An iterator over pre-patched orphans
        :rtype: Iterator[SingletonState]
        """
        return iter(self.orphans_left_lookup.values())

    def orphans_right(self) -> Iterator[SingletonState]:
        """
        Iterates over post-patched orphans

        :return: An iterator over post-patched orphans
        :rtype: Iterator[SingletonState]
        """
        return iter(self.orphans_right_lookup.values())

    def is_compatible(self, state_left: SimState, state_right: SimState) -> bool:
        """
        Returns True when the two input states are compatible based on the pairs stored in this object, and False otherwise.

        :param SimState state_left: The pre-patched state
        :param SimState state_right: The post-patched state
        :return: True if the input states are compatible, and False otherwise
        :rtype: bool
        """
        return (state_left, state_right) in self.pairs

    def __iter__(self) -> Iterator[PairComparison]:
        """
        Iterates over compatible pairs stored in the comparison.

        :return: An iterator over compatible pairs.
        :rtype: Iterator[PairComparison]
        """
        return iter(self.pairs.values())

    def verify(self, verification_assertion: Callable[[PairComparison], claripy.ast.Base]) -> list[PairComparison]:
        """
        Determines what compatible state pairs are valid with respect to a verification assertion. Note that the comparison results are verified with respect to the verification_assertion if the returned list is empty (has length 0).

        :param Callable[[PairComparison], claripy.ast.Base] verification_assertion: A function which takes in a compatible pair and returns a claripy expression which must be satisfiable for all inputs while under the joint constraints of the state pair.
        :return: A list of all compatible pairs for which there was a concrete input that caused the verification assertion to fail.
        :rtype: list[PairComparison]
        """
        failure_list = []
        for ((state_left, state_right), pair_comp) in self.pairs.items():
            joint_solver = claripy.Solver()
            joint_solver.add(state_left.solver.constraints)
            joint_solver.add(state_right.solver.constraints)
            joint_solver.simplify()
            assertion = verification_assertion(pair_comp)
            if joint_solver.satisfiable(~assertion):
                failure_list.append(pair_comp)
        return failure_list

    def report(self, args: any, concrete_arg_mapper: Callable[[any], any] | None=None, num_examples: int=3) -> str:
        """
        Generates a human readable report of the result object, saved as a string. This string is suitable for printing.

        :param any args: The symbolic/concolic arguments used during exeuction, here these args are concretized so that we can give examples of concrete input.
        :param Callable[[any], any] | None concrete_arg_mapper: This function is used to post-process concretized versions of args before they are added to the return string. Some examples of this function include converting an integer to a negative number due to use of two's complement, or slicing off parts of the argument based on another part of the input arguments.
        :param int num_examples: The number of concrete examples to show the user.
        :return: A human readable summary of the comparison.
        :rtype: str
        """
        output = ""
        for p in self.pairs.values():
            i = p.state_left.state_id
            tag_left = p.state_left.state_tag
            j = p.state_right.state_id
            tag_right = p.state_right.state_tag
            if tag_left == tag_right:
                # Check if the registers, memory, stdio are the same for these two states
                is_observationally_equal = p.equal()
                if not is_observationally_equal:
                    output += "STATE PAIR ({}, {}), ({}, {}) are different\n".format(i, str(tag_left), j, str(tag_right))
                    # Memory diff
                    if len(p.mem_diff) == 0:
                        output += "The memory was equal for this state pair\n"
                    else:
                        output += "Memory difference detected for {},{}:\n".format(i, j)
                        output += str(hexify(p.mem_diff))
                        output += "\nInstruction pointers for these memory writes:\n"
                        output += str(hexify(p.mem_diff_ip))
                        output += "\n"
                    # Reg diff
                    if len(p.reg_diff) == 0:
                        output += "The registers were equal for this state pair\n"
                    else:
                        output += "Register difference detected for {},{}:\n".format(i, j)
                        output += str(p.reg_diff)
                        output += "\n"
            else:
                output += "STATE PAIR ({}, {}), ({}, {}) are different\n".format(i, str(tag_left), j, str(tag_right))
                is_observationally_equal = False
            if not is_observationally_equal:
                # Stdio diff
                def compare_std_io(std_io_pre: bytes | None, std_io_post: bytes | None, desc: str):
                    nonlocal output
                    if std_io_pre != std_io_post:
                        output += "There was a difference in {}\n".format(desc)
                        output += "Prepatch {}:\n".format(desc)
                        output += str(std_io_pre)
                        output += "\nPostpatch {}:\n".format(desc)
                        output += str(std_io_post)
                        output += "\n"
                compare_std_io(p.state_left.std_out, p.state_right.std_out, "stdout")
                compare_std_io(p.state_left.std_err, p.state_right.std_err, "stderr")
                # Concrete examples
                if num_examples > 0:
                    concrete_examples = p.concrete_examples(args, num_examples=num_examples)
                    output += "Here are {} concrete input(s) for this particular state pair:\n".format(len(concrete_examples))
                    for (k, concrete_input) in enumerate(concrete_examples):
                        if concrete_arg_mapper is not None:
                            input_args = concrete_arg_mapper(concrete_input.args)
                        else:
                            input_args = hexify(concrete_input.args)
                        output += "{}.\n".format(k + 1)
                        output += "\tInput arguments: {}\n".format(str(input_args))
                        if len(concrete_input.mem_diff) > 0:
                            output += "\tConcrete mem diff: {}\n".format(str(hexify(concrete_input.mem_diff)))
                        if len(concrete_input.reg_diff) > 0:
                            output += "\tConcrete reg diff: {}\n".format(str(hexify(concrete_input.reg_diff)))
                        def print_vprints(vprints):
                            nonlocal output
                            for (pdirective, conc_print_val) in vprints:
                                if pdirective.concrete_mapper is not None:
                                    conc_print_val = pdirective.concrete_mapper(conc_print_val)
                                output += "{}: {}\n".format(pdirective.info_str, conc_print_val)
                        if len(concrete_input.left_vprints) > 0:
                            output += "Prepatched virtual prints:\n"
                            print_vprints(concrete_input.left_vprints)
                        if len(concrete_input.right_vprints) > 0:
                            output += "Postpatched virtual prints:\n"
                            print_vprints(concrete_input.right_vprints)
        def report_orphan_state(orphan: SingletonState):
            nonlocal output
            output += "STATE ({}, {}) is an orphan\n".format(orphan.state_id, str(orphan.state_tag))
            if orphan.std_out is not None:
                output += "stdout: {}\n".format(orphan.std_out)
            if orphan.std_err is not None:
                output += "stderr: {}\n".format(orphan.std_err)
            concrete_examples = orphan.concrete_examples(args, num_examples=num_examples)
            output += "Here are {} concrete input(s) for this particular orphaned state:\n".format(len(concrete_examples))
            for (k, concrete_input) in enumerate(concrete_examples):
                if concrete_arg_mapper is not None:
                    input_args = concrete_arg_mapper(concrete_input.args)
                else:
                    input_args = hexify(concrete_input.args)
                output += "{}.\n".format(k + 1)
                output += "\tInput arguments: {}\n".format(str(input_args))
                if len(concrete_input.vprints) > 0:
                    output += "Prepatched virtual prints:\n"
                    for (pdirective, conc_print_val) in concrete_input.vprints:
                        if pdirective.concrete_mapper is not None:
                            conc_print_val = pdirective.concrete_mapper(conc_print_val)
                        output += "({}, {})\n".format(pdirective.info_str, conc_print_val)

        if len(self.orphans_left_lookup) == 0:
            output += "There are no prepatched orphans\n"
        else:
            output += "PREPATCHED ORPHANS:\n"
            for orphan in self.orphans_left():
                report_orphan_state(orphan)

        if len(self.orphans_right_lookup) == 0:
            output += "There are no postpatched orphans\n"
        else:
            output += "POSTPATCHED ORPHANS:\n"
            for orphan in self.orphans_right():
                report_orphan_state(orphan)

        return output

class ErroredInfo:
    """
    This class is for getting results about errored states, which can be done with only a single RunResult.
    """
    def __init__(self, errored_states: list[ErrorRecord]):
        """
        Constructor for ErrorResults

        :param TerminatedResult result: The results to extract errored states from and analyze.
        """
        self.errored_lookup = dict()
        stdout_fileno = sys.stdout.fileno()
        stderr_fileno = sys.stderr.fileno()

        for (i, error_record) in enumerate(errored_states):
            self.errored_lookup[error_record.state] = SingletonState(
                error_record.state,
                error_record.state.posix.dumps(stdout_fileno),
                error_record.state.posix.dumps(stderr_fileno),
                i, StateTag.ERROR_STATE, error_record.error)

    @staticmethod
    def from_run_result(result: RunResult) -> 'ErroredInfo':
        """
        Creates an ErroredInfo object from a RunResult, passing the errored field to the constructor.

        :param RunResult result: The result for which we wish to analyze any associated errored states.
        :return: An ErroredInfo object which contains information about the errored states.
        :rtype: ErroredInfo
        """
        return ErroredInfo(result.errored)

    def get_errored_singleton(self, state: SimState) -> SingletonState:
        """
        Returns the SingletonState associated with some errored SimState

        :param SimState state: The state for which we should find a corresponding SingletonState
        """
        return self.errored_lookup[state]

    def __iter__(self) -> Iterator[SingletonState]:
        """
        Iterates over the SingletonState errored states stored in this object

        :return: An iterator over errored SingletonStates.
        :rtype: Iterator[SingletonState]
        """
        return iter(self.errored_lookup.values())

    def report(self, args: any, concrete_arg_mapper: Callable[[any], any] | None = None, num_examples: int = 3) -> str:
        """
        Creates a human readable report about a list of errored states.

        :param any args: The arguments to concretize
        :param Callable[[any], any] | None concrete_arg_mapper: This function is used to post-process concretized versions of args before they are added to the return string. Some examples of this function include converting an integer to a negative number due to use of two's complement, or slicing off parts of the argument based on another part of the input arguments.
        :param int num_examples: The maximum number of concrete examples to show the user for each errored state.
        :return: The report as a string
        :rtype: str
        """
        output = ""
        for err in self.errored_lookup.values():
            output += "Error State #{}\n".format(err.state_id)
            output += "{}\n".format(err.error_info)
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

class AssertFailedInfo:
    """
    This class is for getting results about assertion failed states, which can be done with only a single RunResult.

    :ivar list[SingletonState] singleton_states: Information about the assertion failed state.
    :ivar list[AssertFailed] asserts_failed: The assertions that failed
    """
    def __init__(self, asserts_failed: list[AssertFailed]):
        """
        Constructor for AssertFailedInfo. This constructor will create a SingletonState for each failed assertion.

        :param list[AssertFailed] asserts_failed: The assertions that we wish to analyze and report on.
        """
        self.asserts_failed = asserts_failed
        stdout_fileno = sys.stdout.fileno()
        stderr_fileno = sys.stderr.fileno()
        self.singleton_states = [
            SingletonState(assert_failed.failure_state,
                           assert_failed.failure_state.posix.dumps(stdout_fileno),
                           assert_failed.failure_state.posix.dumps(stderr_fileno),
                           i, StateTag.ASSERT_FAILED_STATE,
                           error_info=assert_failed.assertion.info_str)
            for (i, assert_failed) in enumerate(asserts_failed)
        ]

    @staticmethod
    def from_run_result(result: RunResult) -> 'AssertFailedInfo':
        """
        Creates an AssertFailedInfo object from a RunResult, passing the asserts_failed field to the constructor.

        :param RunResult result: The result for which we wish to analyze any associated assertions.
        :return: An AssertFailedInfo object which contains information about the failed assertions.
        :rtype: AssertFailedInfo
        """
        return AssertFailedInfo(result.asserts_failed)

    def report(self, args: any, concrete_arg_mapper: Callable[[any], any] | None = None, num_examples: int = 3) -> str:
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
            for (assert_failed, singleton_state) in zip(self.asserts_failed, self.singleton_states):
                output += "Assert for address {} was triggered: {}\n".format(hex(assert_failed.assertion.addr), str(assert_failed.cond))
                if assert_failed.assertion.info_str is not None:
                    output += assert_failed.assertion.info_str + "\n"
                concrete_inputs = singleton_state.concrete_examples(args, num_examples)
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