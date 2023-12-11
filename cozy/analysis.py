from collections.abc import Iterator

import claripy
from angr import SimState

import portion as P

from angr.state_plugins import SimStateHistory
from . import claripy_ext
from .functools_ext import *
import collections.abc
from .project import RunResult
from .concrete import _concretize, CompatiblePairInput
from .terminal_state import TerminalState, DeadendedState

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

    def __init__(self):
        self.cores: list[frozenset[claripy.ast.bool]] = []

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

        # If any previously discovered unsat core is a subset of the current constraints, then the current
        # joint constraints are automatically unsatisfiable.
        constraints = frozenset(sl.solver.constraints + sr.solver.constraints)
        for core in self.cores:
            if core.issubset(constraints):
                return None

        # The reason we are adding constraints from both states is that we
        # want to get a joint system that constrains the input arguments
        # angr may generate additional internal constraints as the function is symbolically executed
        # these generated symbols will be fresh. In contrast, the input arguments
        # will be the same symbol for both functions
        joint_solver = claripy.Solver(track=True) # The track parameter is required to generate an unsat core
        joint_solver.add(sl.solver.constraints)
        joint_solver.add(sr.solver.constraints)

        # If joint_solver is not satisfiable, that means that the constrained set of possible
        # inputs to the function is the empty set. This means that these two states could not
        # have been reached with a given input, and we can therefore disregard this comparison
        if not (joint_solver.satisfiable()):
            core = frozenset(joint_solver.unsat_core())
            self.cores.append(core)
            return None

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

class CompatiblePair:
    """
    Stores information about comparing two compatible states.

    :ivar TerminalState state_left: Information pertaining specifically to the pre-patched state being compared.
    :ivar TerminalState state_right: Information pertaining specifically to the post-patched state being compared.
    :ivar dict[range, tuple[claripy.ast.Base, claripy.ast.Base]] mem_diff: Maps memory addresses to pairs of claripy ASTs, where the left element of the tuple is the data in memory for state_left, and the right element of the tuple is what was found in memory for state_right. Only memory locations that are different are saved in this dict.
    :ivar dict[str, tuple[claripy.ast.Base, claripy.ast.Base]] reg_diff: Similar to mem_diff, except that the dict is keyed by register names. Note that some registers may be subparts of another. For example in x64, EAX is a subregister of RAX.
    :ivar dict[int, tuple[frozenset[claripy.ast.Base]], frozenset[claripy.ast.Base]] mem_diff_ip: Maps memory addresses to a set of instruction pointers that the program was at when it wrote that byte in memory. In most cases the frozensets will have a single element, but this may not be the case in the scenario where a symbolic value determined the write address.
    :ivar bool compare_std_out: If True then we should consider stdout when checking if the two input states are equal.
    :ivar bool compare_std_err: If True then we should consider stderr when checking if the two input states are equal.
    """

    def __init__(self,
                 state_left: TerminalState,
                 state_right: TerminalState,
                 mem_diff: dict[range, tuple[claripy.ast.Base, claripy.ast.Base]],
                 # TODO: Expose the subregister structure somewhere
                 reg_diff: dict[str, tuple[claripy.ast.Base, claripy.ast.Base]],
                 mem_diff_ip: dict[int, tuple[frozenset[claripy.ast.Base]], frozenset[claripy.ast.Base]],
                 compare_std_out: bool,
                 compare_std_err: bool):
        self.state_left = state_left
        self.state_right = state_right
        self.mem_diff = mem_diff
        self.reg_diff = reg_diff
        self.mem_diff_ip = mem_diff_ip
        self.compare_std_out = compare_std_out
        self.compare_std_err = compare_std_err

    def equal(self) -> bool:
        """
        Determines if the two compatible states are observationally equal. That is, they contain the same memory contents, registers, stdout, and stderr after execution.

        :return: True if the two compatible states are observationally equal, and False otherwise.
        :rtype: bool
        """
        if isinstance(self.state_left, DeadendedState) and isinstance(self.state_right, DeadendedState):
            return (len(self.mem_diff) == 0 and len(self.reg_diff) == 0 and
                    ((not self.compare_std_out) or (self.state_left.std_out == self.state_right.std_out)) and
                    ((not self.compare_std_err) or (self.state_left.std_err == self.state_right.std_err)))
        else:
            return False

    def concrete_examples(self, args: any, num_examples=3) -> list[CompatiblePairInput]:
        """
        Concretizes the arguments used to put the program in these states by jointly using the constraints attached to the compatible states.

        :param any args: The input arguments to concretize. This argument may be a Python datastructure, the concretizer will make a deep copy with claripy symbolic variables replaced with concrete values.
        :param int num_examples: The maximum number of concrete examples to generate for this particular pair.
        :return: A list of concrete inputs that satisfy both constraints attached to the states.
        :rtype: list[CompatiblePairInput]
        """
        sl = self.state_left.state
        sr = self.state_right.state
        joint_solver = claripy.Solver()
        joint_solver.add(sl.solver.constraints)
        joint_solver.add(sr.solver.constraints)
        state_bundle = (args, self.mem_diff, self.reg_diff, self.state_left.virtual_prints, self.state_right.virtual_prints)
        concrete_results = _concretize(joint_solver, state_bundle, n=num_examples)
        return [CompatiblePairInput(conc_args, conc_mem_diff, conc_reg_diff, conc_vprints_left, conc_vprints_right)
                for (conc_args, conc_mem_diff, conc_reg_diff, conc_vprints_left, conc_vprints_right) in
                concrete_results]

class Comparison:
    """
    This class stores all compatible pairs and orphaned states. An orphan state is one in which there is no compatible state in the other execution tree. In most scenarios there will be no orphaned states.

    :ivar dict[tuple[SimState, SimState], CompatiblePair] pairs: pairs stores a dictionary that maps a pair of (pre_patch_state, post_patch_state) compatible states to their comparison information
    :ivar set[TerminalState] orphans_left: Pre-patched states for which there are 0 corresponding compatible states in the post-patch
    :ivar set[TerminalState] orphans_right: Post-patched states for which there are 0 corresponding compatible states in the pre-patch
    """

    def __init__(self, pre_patched: RunResult, post_patched: RunResult, ignore_addrs: list[range] | None = None,
                 ignore_invalid_stack=True, compare_memory=True, compare_registers=True, compare_std_out=False,
                 compare_std_err=False):
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
        """

        if ignore_addrs is None:
            ignore_addrs = []

        self.pairs: dict[tuple[SimState, SimState], CompatiblePair] = dict()

        states_pre_patched: list[TerminalState] = pre_patched.deadended + pre_patched.errored + pre_patched.asserts_failed
        states_post_patched: list[TerminalState] = post_patched.deadended + post_patched.errored + post_patched.asserts_failed

        # An orphan is a state that is not compatible with any other state
        # Testing has revealed that there are typically never any orphans
        self.orphans_left: set[TerminalState] = set(states_pre_patched)
        self.orphans_right: set[TerminalState] = set(states_post_patched)

        memoized_diff = StateDiff()

        # If ignore_invalid_stack is enabled, then any data that was stored on the stack in the past,
        # but is now invalid due to movement of the stack pointer is ignored
        if ignore_invalid_stack:
            inv_addrs_pre_patched = [_invalid_stack_addrs(term_state.state) for term_state in states_pre_patched]
            inv_addrs_post_patched = [_invalid_stack_addrs(term_state.state) for term_state in states_post_patched]
        else:
            inv_addrs_pre_patched = None
            inv_addrs_post_patched = None

        for (i, state_pre) in enumerate(states_pre_patched):
            for (j, state_post) in enumerate(states_post_patched):
                if ignore_invalid_stack:
                    stack_change = state_pre.state.arch.stack_change
                    pair_ignore_addrs = ignore_addrs + [_invalid_stack_overlap(inv_addrs_pre_patched[i], inv_addrs_post_patched[j], stack_change)]
                else:
                    pair_ignore_addrs = ignore_addrs

                is_deadended_comparison = isinstance(state_pre, DeadendedState) and isinstance(state_post, DeadendedState)

                diff = memoized_diff.difference(
                    state_pre.state, state_post.state, pair_ignore_addrs,
                    compute_mem_diff=compare_memory if is_deadended_comparison else False,
                    compute_reg_diff=compare_registers if is_deadended_comparison else False
                )

                if diff is not None:
                    # These states are compatible, so remove them from the orphans sets
                    self.orphans_left.discard(state_pre)
                    self.orphans_right.discard(state_post)

                    (mem_diff, reg_diff) = diff

                    def get_ip_set(interval_dict, r: range):
                        # Query the interval dictionary for all entries in the desired range, then union
                        # all of those sets together
                        ip_sets = [s for (n, s) in interval_dict[P.closedopen(r.start, r.stop)].values()]
                        return frozenset().union(*ip_sets)

                    mem_diff_ip = {
                        addr_range: (get_ip_set(state_post.mem_writes, addr_range), get_ip_set(state_pre.mem_writes, addr_range))
                        for addr_range in mem_diff.keys()
                    }

                    comparison = CompatiblePair(state_pre, state_post, mem_diff, reg_diff, mem_diff_ip, compare_std_out, compare_std_err)
                    self.pairs[(state_pre.state, state_post.state)] = comparison

    def get_pair(self, state_left: SimState, state_right: SimState) -> CompatiblePair:
        """
        Retrieves a CompatiblePair given two compatible input states.

        :param SimState state_left: The pre-patched state
        :param SimState state_right: The post-patched state
        :return: The CompatiblePair object corresponding to this compatible state pair.
        :rtype: CompatiblePair
        """
        return self.pairs[(state_left, state_right)]

    def is_compatible(self, state_left: SimState, state_right: SimState) -> bool:
        """
        Returns True when the two input states are compatible based on the pairs stored in this object, and False otherwise.

        :param SimState state_left: The pre-patched state
        :param SimState state_right: The post-patched state
        :return: True if the input states are compatible, and False otherwise
        :rtype: bool
        """
        return (state_left, state_right) in self.pairs

    def __iter__(self) -> Iterator[CompatiblePair]:
        """
        Iterates over compatible pairs stored in the comparison.

        :return: An iterator over compatible pairs.
        :rtype: Iterator[CompatiblePair]
        """
        return iter(self.pairs.values())

    def verify(self, verification_assertion: Callable[[CompatiblePair], claripy.ast.Base]) -> list[CompatiblePair]:
        """
        Determines what compatible state pairs are valid with respect to a verification assertion. Note that the comparison results are verified with respect to the verification_assertion if the returned list is empty (has length 0).

        :param Callable[[CompatiblePair], claripy.ast.Base] verification_assertion: A function which takes in a compatible pair and returns a claripy expression which must be satisfiable for all inputs while under the joint constraints of the state pair.
        :return: A list of all compatible pairs for which there was a concrete input that caused the verification assertion to fail.
        :rtype: list[CompatiblePair]
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
        Generates a human-readable report of the result object, saved as a string. This string is suitable for printing.

        :param any args: The symbolic/concolic arguments used during exeuction, here these args are concretized so that we can give examples of concrete input.
        :param Callable[[any], any] | None concrete_arg_mapper: This function is used to post-process concretized versions of args before they are added to the return string. Some examples of this function include converting an integer to a negative number due to use of two's complement, or slicing off parts of the argument based on another part of the input arguments.
        :param int num_examples: The number of concrete examples to show the user.
        :return: A human-readable summary of the comparison.
        :rtype: str
        """

        output = ""
        for p in self.pairs.values():
            i = p.state_left.state_id
            j = p.state_right.state_id
            # Check if the registers, memory, stdio are the same for these two states
            is_observationally_equal = p.equal()
            if not is_observationally_equal:
                output += "STATE PAIR ({}, {}), ({}, {}) are different\n".format(i, p.state_left.state_type_str, j, p.state_right.state_type_str)

                if type(p.state_left) is type(p.state_right):
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
                    output += "Skipped memory and register differencing since the type of these two states are different.\n"

                # Stdio diff
                def compare_std_io(std_io_pre: bytes, std_io_post: bytes, desc: str):
                    nonlocal output
                    if std_io_pre != std_io_post:
                        output += "There was a difference in {}\n".format(desc)
                        output += "Prepatch {}:\n".format(desc)
                        output += str(std_io_pre)
                        output += "\nPostpatch {}:\n".format(desc)
                        output += str(std_io_post)
                        output += "\n"
                if p.compare_std_out:
                    compare_std_io(p.state_left.std_out, p.state_right.std_out, "stdout")
                if p.compare_std_err:
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

                output += "\n"

        def report_orphan_state(orphan: TerminalState):
            nonlocal output
            output += "STATE ({}, {}) is an orphan\n".format(orphan.state_id, orphan.state_type_str)
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

        if len(self.orphans_left) == 0:
            output += "There are no prepatched orphans\n"
        else:
            output += "PREPATCHED ORPHANS:\n"
            for orphan in self.orphans_left:
                report_orphan_state(orphan)

        if len(self.orphans_right) == 0:
            output += "There are no postpatched orphans\n"
        else:
            output += "POSTPATCHED ORPHANS:\n"
            for orphan in self.orphans_right:
                report_orphan_state(orphan)

        return output
