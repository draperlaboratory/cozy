from collections.abc import Iterator

import claripy
import z3.z3types
from angr import SimState

import portion as P

import cozy.log
from . import claripy_ext, log, side_effect
from .functools_ext import *
import collections.abc
from .session import RunResult
from .concrete import _concretize, CompatiblePairInput
from .side_effect import PerformedSideEffect, ConcretePerformedSideEffect
from .terminal_state import TerminalState, DeadendedState

# Given a state, returns a range of addresses that were used as part of the stack but are no longer
# valid stack locations. This will happen if the stack grows, then shrinks.
def _invalid_stack_addrs(st: SimState) -> range:
    # Note that state.callback.stack_ptr has given incorrect values in the
    # lunarrelaysat test case. It seems that state.regs.sp is correct there,
    # so use that instead. In most cases state.regs.sp should be concrete,
    # but we take the min/max anyway
    #curr_sp = st.callstack.stack_ptr

    # The red page is at the extrema of the stack, so we can use that to determine
    # the addresses to diqualify
    red_page_addr = st.memory._red_pageno * st.memory.page_size
    if st.arch.stack_change < 0:
        # The stack grows down
        curr_sp = st.solver.max(st.regs.sp)
        return range(red_page_addr, curr_sp)
    else:
        # The stack grows up
        curr_sp = st.solver.min(st.regs.sp)
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

def _stack_addrs(st: SimState) -> range:
    stack_start = st.arch.initial_sp
    curr_sp = st.solver.max(st.regs.sp)
    #curr_sp = st.callstack.stack_ptr

    if st.arch.stack_change < 0:
        # The stack grows down
        return range(curr_sp, stack_start + 1)
    else:
        # The stack grows up
        return range(stack_start, curr_sp + 1)

def nice_name(state: SimState, malloced_names: P.IntervalDict[tuple[str, P.Interval]], addr: int) -> str | None:
    """
    This function attempts to create a human understandable name for an address, or returns None if it can't figure
    one out.
    """

    # Python malloced blocks
    malloced_mem_info = malloced_names.get(addr)
    if malloced_mem_info is not None:
        (name, interval) = malloced_mem_info
        start_addr = interval.lower
        offset = addr - start_addr
        return "{}+{}".format(name, hex(offset))

    # Stack addresses
    stack_range = _stack_addrs(state)
    # Expand the range slightly as a heuristic
    wider_range = range(stack_range.start - 1024, stack_range.stop + 1024)
    if addr in wider_range:
        # Note that state.callback.stack_ptr has given incorrect values in the
        # lunarrelaysat test case. It seems that state.regs.sp is correct there,
        # so use that instead. In most cases state.regs.sp should be concrete,
        # but we take the max anyway
        #stack_ptr = state.callstack.stack_ptr

        stack_ptr = state.solver.max(state.regs.sp)
        offset = addr - stack_ptr
        if offset < 0:
            return "sp{}".format(hex(offset))
        else:
            return "sp+{}".format(hex(offset))

    return None

class FieldDiff:
    pass

class EqFieldDiff(FieldDiff):
    """
    For a field to be equal, all subcomponents of the body must be equal. In this case, left_body and right_body
    should not hold any further FieldDiffs within themselves. Rather left_body and right_body should be the entire
    fields for which differencing was checked (and it was determined that all subfields are equal).
    """
    def __init__(self, left_body, right_body):
        self.left_body = left_body
        self.right_body = right_body

class NotEqLeaf(FieldDiff):
    """
    A not equal leaf is a field that cannot be further unpacked/traversed.
    """
    def __init__(self, left_leaf, right_leaf):
        self.left_leaf = left_leaf
        self.right_leaf = right_leaf

class NotEqFieldDiff(FieldDiff):
    """
    For a field to be not equal, there must be at least one subcomponent of the body that was not equal. In this case,
    body_diff will hold further FieldDiffs within itself. Equal subfields of the bodies will be
    represented by EqFieldDiff, whereas unequal subfields will be represented by further nested NotEqFieldDiff.
    """
    def __init__(self, body_diff):
        # body_diff is a zipped data structure. For example, if body_diff is a list, it will be a list of FieldDiff
        # objects, one for each zipped element. If body_diff is a dict, it will be a dict with string keys, and values
        # of FieldDiff objects.
        self.body_diff = body_diff

def compare_side_effect(joint_solver, left_se, right_se) -> FieldDiff:
    both_lists = isinstance(left_se, list) and isinstance(right_se, list)
    both_tuples = isinstance(left_se, tuple) and isinstance(right_se, tuple)
    # List, tuple case
    if both_lists or both_tuples:
        max_len = max(len(left_se), len(right_se))
        subfields_equal = True
        diff = []
        # Loop over the zipped lists
        for i in range(max_len):
            if i < len(left_se):
                left_val = left_se[i]
            else:
                left_val = None
            if i < len(right_se):
                right_val = right_se[i]
            else:
                right_val = None
            # Compare each element of the list
            rec_result = compare_side_effect(joint_solver, left_val, right_val)
            if not isinstance(rec_result, EqFieldDiff):
                # The element in the list are not equal, so the overall list is not equal
                subfields_equal = False
            diff.append(rec_result)
        if subfields_equal:
            # All elements in the list are equal, so the overall lists are equal
            return EqFieldDiff(left_se, right_se)
        else:
            # There was at least one element that was not equal, so return the zipped diff
            if both_tuples:
                diff = tuple(diff)
            return NotEqFieldDiff(diff)
    # dict case
    elif isinstance(left_se, dict) and isinstance(right_se, dict):
        all_keys = set(left_se.keys())
        all_keys.update(right_se.keys())
        subfields_equal = True
        diff = dict()
        # Compute the diff for all entries in the dictionary
        for key in all_keys:
            left_val = left_se.get(key, None)
            right_val = right_se.get(key, None)
            # Compare each value in the dictionary
            rec_result = compare_side_effect(joint_solver, left_val, right_val)
            if not isinstance(rec_result, EqFieldDiff):
                # The value in the dictionary was not equal, so the overall dicts are not equal
                subfields_equal = False
            diff[key] = rec_result
        if subfields_equal:
            return EqFieldDiff(left_se, right_se)
        else:
            return NotEqFieldDiff(diff)
    # claripy ast case
    elif isinstance(left_se, claripy.ast.Bits) and isinstance(right_se, claripy.ast.Bits):
        def is_sat():
            try:
                return joint_solver.satisfiable(extra_constraints=[left_se != right_se])
            except claripy.ClaripyZ3Error as err:
                cozy.log.error("Unable to solve SMT formula when comparing side effects. The SMT solver returned unknown instead of SAT or UNSAT. We will assume that there is some way to make these side effects not equal.\nThe exception thrown was:\n{}", str(err))
                return True
            except claripy.ClaripySolverInterruptError as err:
                cozy.log.error("Unable to solve SMT formula when comparing side effects. The SMT solver was interrupted, most likely due to resource exhaustion. We will assume that there is some way to make these side effects not equal.\nThe exception thrown was:\n{}", str(err))
                return True

        if left_se is not right_se and is_sat():
            # Base case: leaf elements are not equal
            return NotEqLeaf(left_se, right_se)
        else:
            return EqFieldDiff(left_se, right_se)
    # int or string case
    elif (isinstance(left_se, int) and isinstance(right_se, int)) or (
            isinstance(left_se, str) and isinstance(right_se, str)):
        if left_se == right_se:
            return EqFieldDiff(left_se, right_se)
        else:
            return NotEqLeaf(left_se, right_se)
    # catchall base case. This will be hit if one of the values we were comparing was None, which is what we want
    else:
        return NotEqLeaf(left_se, right_se)

class DiffResult:
    def __init__(self,
                 mem_diff: dict[range, tuple[claripy.ast.bits, claripy.ast.bits]],
                 reg_diff: dict[str, tuple[claripy.ast.bits, claripy.ast.bits]],
                 side_effect_diff: dict[str, list[tuple[PerformedSideEffect | None, PerformedSideEffect | None, FieldDiff]]]):
        self.mem_diff = mem_diff
        self.reg_diff = reg_diff
        self.side_effect_diff = side_effect_diff

class StateDiff:
    """
    StateDiff encapsulates the memoized state used by the difference method. This class is used internally by\
    Comparison and is typically not for external use.
    """

    def __init__(self):
        self.cores: list[frozenset[claripy.ast.bool]] = []

    def difference(self,
                   sl: SimState, sr: SimState,
                   ignore_addrs: collections.abc.Iterable[range] | None = None,
                   compute_mem_diff=True,
                   compute_reg_diff=True,
                   compute_side_effect_diff=True,
                   use_unsat_core=True,
                   simplify=False) -> DiffResult | None:
        """
        Compares two states to find differences in memory. This function will return None if the two states have\
        non-intersecting inputs. Otherwise, it will return a dict of addresses and a dict of registers which are\
        different between the two. This function is based off of\
        angr.analyses.congruency_check.CongruencyCheck().compare_states, but has been customized for our purposes. Note\
        that this function may use memoization to enhance performance.

        :param SimState sl: The first state to compare
        :param SimState sr: The second state to compare
        :param collections.abc.Iterable[range] | None ignore_addrs: Memory addresses to ignore when doing the memory\
        diffing. This representation is more efficient than a set of integers since the ranges involved can be quite\
        large.
        :param bool compute_mem_diff: If this flag is True, then we will diff the memory. If this is false, then the\
        first element of the return tuple will be None.
        :param bool compute_reg_diff: If this flag is True, then we will diff the registers. If this is false, then the\
        second element of the return tuple will be None.
        :param bool use_unsat_core: If this flag is True, then we will use unsat core optimization to speed up\
        comparison of pairs of states. This option may cause errors in Z3, so disable if this occurs.
        :return: None if the two states are not compatible, otherwise returns an object containing the memory,\
        register differences, and side effect differences.
        :rtype: DiffResult | None
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
        joint_solver = claripy.Solver(track=use_unsat_core) # The track parameter is required to generate an unsat core
        joint_solver.add(sl.solver.constraints)
        joint_solver.add(sr.solver.constraints)

        try:
            is_sat = joint_solver.satisfiable()
        except claripy.ClaripyZ3Error as err:
            cozy.log.error("Unable to determine if two states are compatible. The SMT solver returned unknown instead of SAT or UNSAT. We will assume that there is some way to make these two states compatible in our report. Note that there is unlikely to be any concrete examples generated for this pair.\nThe exception thrown was:\n{}", str(err))
            is_sat = True
        except claripy.ClaripySolverInterruptError as err:
            cozy.log.error("Unable to determine if two states are compatible. The SMT solver was interrupted, most likely due to resource exhaustion. We will assume that there is some way to make these two states compatible in our report. Note that there is unlikely to be any concrete examples generated for this pair.\nThe exception thrown was:\n{}", str(err))
            is_sat = True

        # If joint_solver is not satisfiable, that means that the constrained set of possible
        # inputs to the function is the empty set. This means that these two states could not
        # have been reached with a given input, and we can therefore disregard this comparison
        if not is_sat:
            if use_unsat_core:
                core = frozenset(joint_solver.unsat_core())
                self.cores.append(core)
            return None

        ret_mem_diff = dict()

        # Compute memory difference
        if compute_mem_diff:
            left_mem_writes = sl.globals['mem_writes']
            right_mem_writes = sr.globals['mem_writes']

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
                    # Note that the joint solver caches models that previously led to satness. This means that in the
                    # case where the following condition is satisfiable, angr may internally not query z3 at all.
                    # There is not much point in adding the unsat core trick here, since we already know that the joint
                    # solver constraints without the extra_constraints are satisfiable. bytes_left != bytes_right are
                    # highly likely to be syntactically different from previous calls of this loop as well.

                    try:
                        is_sat = joint_solver.satisfiable(extra_constraints=[bytes_left != bytes_right])
                    except claripy.ClaripyZ3Error as err:
                        cozy.log.error("Unable to determine if memory contents at {} .. {} are equal or not. The SMT solver returned unknown instead of SAT or UNSAT. We will assume that there is some way to make these bytes not equal in our report.\nThe exception thrown was:\n{}", hex(addr_range.start), hex(addr_range.start + len(addr_range) - 1), str(err))
                        is_sat = True
                    except claripy.ClaripySolverInterruptError as err:
                        cozy.log.error("Unable to determine if memory contents at {} .. {} are equal or not. The SMT solver was interrupted, most likely due to resource exhaustion. We will assume that there is some way to make these bytes not equal in our report.\nThe exception thrown was:\n{}", hex(addr_range.start), hex(addr_range.start + len(addr_range) - 1), str(err))
                        is_sat = True

                    if is_sat:
                        # It is possible that there is a symbolic value stored in memory.
                        # Here we want to simplify this with respect to the joint constraints
                        if simplify:
                            bytes_left = claripy_ext.simplify_kb(bytes_left, joint_solver.constraints)
                            bytes_right = claripy_ext.simplify_kb(bytes_right, joint_solver.constraints)
                        # It is possible that there is a symbolic value stored in memory.
                        ret_mem_diff[addr_range] = (bytes_left, bytes_right)

        # Loop over all the registers that could possibly be different and save the ones that are actually different
        ret_reg_diff = dict()

        # Compute register difference
        if compute_reg_diff:
            for reg_name in dir(sl.regs):
                # Ignore registers that start with underscore and cc pseudoregisters (which appear to be a part of the VEX
                # framework used by angr)
                if reg_name.startswith("_") or reg_name.startswith("cc_"):
                    continue

                reg_left = getattr(sl.regs, reg_name)
                reg_right = getattr(sr.regs, reg_name)

                if reg_left is not reg_right:
                    try:
                        is_sat = joint_solver.satisfiable(extra_constraints=[reg_left != reg_right])
                    except claripy.ClaripyZ3Error as err:
                        cozy.log.error("Unable to determine if register {} is equal or not. The SMT solver returned unknown instead of SAT or UNSAT. We will assume that there is some way to make these bytes not equal in our report.\nThe exception thrown was:\n{}", reg_name, str(err))
                        is_sat = True
                    except claripy.ClaripySolverInterruptError as err:
                        cozy.log.error("Unable to determine if register {} is equal or not. The SMT solver was interrupted, most likely due to resource exhaustion. We will assume that there is some way to make these bytes not equal in our report.\nThe exception thrown was:\n{}", reg_name, str(err))
                        is_sat = True

                    if is_sat:
                        if simplify:
                            reg_left = claripy_ext.simplify_kb(reg_left, joint_solver.constraints)
                            reg_right = claripy_ext.simplify_kb(reg_right, joint_solver.constraints)
                        ret_reg_diff[reg_name] = (reg_left, reg_right)

        # Compute side effect difference
        ret_side_effect_diff = dict()
        if compute_side_effect_diff:
            left_effects = side_effect.get_effects(sl)
            right_effects = side_effect.get_effects(sr)
            all_channels = set(left_effects.keys())
            all_channels.update(right_effects.keys())
            for channel in all_channels:
                left_channel = left_effects.get(channel, [])
                right_channel = right_effects.get(channel, [])

                aligned_channels = side_effect.levenshtein_alignment(left_channel, right_channel, key=lambda effect: effect.label)

                diff = []
                for (left_effect, right_effect) in aligned_channels:
                    if left_effect is not None and right_effect is not None:
                        comparison_results = compare_side_effect(joint_solver, left_effect.body, right_effect.body)
                        diff.append((left_effect, right_effect, comparison_results))
                    else:
                        left_val = left_effect.body if left_effect is not None else None
                        right_val = right_effect.body if right_effect is not None else None
                        diff.append((left_effect, right_effect, NotEqLeaf(left_val, right_val)))

                ret_side_effect_diff[channel] = diff

        return DiffResult(ret_mem_diff, ret_reg_diff, ret_side_effect_diff)

def hexify(val0):
    """
    Recursively transforms all integers in a Python datastructure (that is mappable with functools_ext.fmap) to hex strings.

    :param val0: The datastructure to traverse.
    :return: A deep copy of the datastructure, with all integers converted to hex strings.
    """
    def f(val1):
        if isinstance(val1, int):
            return hex(val1)
        elif isinstance(val1, range):
            return "range({}, {})".format(hex(val1.start), hex(val1.stop))
        else:
            return val1
    return fmap(val0, f)

class CompatiblePair:
    """
    Stores information about comparing two compatible states.

    :ivar TerminalState state_left: Information pertaining specifically to the pre-patched state being compared.
    :ivar TerminalState state_right: Information pertaining specifically to the post-patched state being compared.
    :ivar dict[range, tuple[claripy.ast.Base, claripy.ast.Base]] mem_diff: Maps memory addresses to pairs of claripy\
    ASTs, where the left element of the tuple is the data in memory for state_left, and the right element of the tuple\
    is what was found in memory for state_right. Only memory locations that are different are saved in this dict.
    :ivar dict[str, tuple[claripy.ast.Base, claripy.ast.Base]] reg_diff: Similar to mem_diff, except that the dict is\
    keyed by register names. Note that some registers may be subparts of another. For example in x64, EAX is a\
    subregister of RAX.
    :ivar dict[str, list[tuple[PerformedSideEffect | None, PerformedSideEffect | None, FieldDiff]]] side_effect_diff: \
    Maps side effect channels to a list of 3 element tuples, where the first element is the performed side effect\
    from the left binary, the second element is the performed side effect from the right binary, and the third element\
    is the diff between the body of the side effects.
    :ivar dict[int, tuple[frozenset[claripy.ast.Base]], frozenset[claripy.ast.Base]] mem_diff_ip: Maps memory addresses\
    to a set of instruction pointers that the program was at when it wrote that byte in memory. In most cases the\
    frozensets will have a single element, but this may not be the case in the scenario where a symbolic value\
    determined the write address.
    :ivar bool compare_std_out: If True then we should consider stdout when checking if the two input states are equal.
    :ivar bool compare_std_err: If True then we should consider stderr when checking if the two input states are equal.
    """

    def __init__(self,
                 state_left: TerminalState,
                 state_right: TerminalState,
                 mem_diff: dict[range, tuple[claripy.ast.Base, claripy.ast.Base]],
                 # TODO: Expose the subregister structure somewhere
                 reg_diff: dict[str, tuple[claripy.ast.Base, claripy.ast.Base]],
                 side_effect_diff: dict[str, list[tuple[PerformedSideEffect | None, PerformedSideEffect | None, FieldDiff]]],
                 mem_diff_ip: dict[int, tuple[frozenset[claripy.ast.Base]], frozenset[claripy.ast.Base]],
                 compare_std_out: bool,
                 compare_std_err: bool):
        self.state_left = state_left
        self.state_right = state_right
        self.mem_diff = mem_diff
        self.reg_diff = reg_diff
        self.side_effect_diff = side_effect_diff
        self.mem_diff_ip = mem_diff_ip
        self.compare_std_out = compare_std_out
        self.compare_std_err = compare_std_err

    def equal_side_effects(self) -> bool:
        for channel in self.side_effect_diff.values():
            for (left_performed_effect, right_performed_effect, field_diff) in channel:
                if not isinstance(field_diff, EqFieldDiff):
                    return False
        return True

    def equal(self) -> bool:
        """
        Determines if the two compatible states are observationally equal. That is, they contain the same memory\
        contents, registers, stdout, and stderr after execution.

        :return: True if the two compatible states are observationally equal, and False otherwise.
        :rtype: bool
        """

        if isinstance(self.state_left, DeadendedState) and isinstance(self.state_right, DeadendedState):
            return (len(self.mem_diff) == 0 and len(self.reg_diff) == 0 and
                    ((not self.compare_std_out) or (self.state_left.std_out == self.state_right.std_out)) and
                    ((not self.compare_std_err) or (self.state_left.std_err == self.state_right.std_err)) and
                    self.equal_side_effects())
        else:
            return False

    def concrete_examples(self, args: any, num_examples=3) -> list[CompatiblePairInput]:
        """
        Concretizes the arguments used to put the program in these states by jointly using the constraints attached to\
        the compatible states.

        :param any args: The input arguments to concretize. This argument may be a Python datastructure, the\
        concretizer will make a deep copy with claripy symbolic variables replaced with concrete values.
        :param int num_examples: The maximum number of concrete examples to generate for this particular pair.
        :return: A list of concrete inputs that satisfy both constraints attached to the states.
        :rtype: list[CompatiblePairInput]
        """
        sl = self.state_left.state
        sr = self.state_right.state
        joint_solver = claripy.Solver()
        joint_solver.add(sl.solver.constraints)
        joint_solver.add(sr.solver.constraints)

        rangeless_mem_diff = {(rng.start, rng.stop): val for (rng, val) in self.mem_diff.items()}
        state_bundle = (args, rangeless_mem_diff, self.reg_diff, self.state_left.side_effects, self.state_right.side_effects)
        concrete_results = _concretize(joint_solver, state_bundle, n=num_examples)

        ret = []
        for (conc_args, conc_mem_diff, conc_reg_diff, conc_side_effects_left, conc_side_effects_right) in concrete_results:
            range_conc_mem_diff = {range(start, stop): val for ((start, stop), val) in conc_mem_diff.items()}
            ret.append(CompatiblePairInput(conc_args, range_conc_mem_diff, conc_reg_diff,
                                           conc_side_effects_left, conc_side_effects_right))

        return ret

class Comparison:
    """
    This class stores all compatible pairs and orphaned states. An orphan state is one in which there is no compatible\
    state in the other execution tree. In most scenarios there will be no orphaned states.

    :ivar dict[tuple[SimState, SimState], CompatiblePair] pairs: pairs stores a dictionary that maps a pair of\
    (pre_patch_state, post_patch_state) compatible states to their comparison information
    :ivar set[TerminalState] orphans_left: Pre-patched states for which there are 0 corresponding compatible states in\
    the post-patch
    :ivar set[TerminalState] orphans_right: Post-patched states for which there are 0 corresponding compatible states\
    in the pre-patch
    """

    def __init__(self, pre_patched: RunResult, post_patched: RunResult, ignore_addrs: list[range] | None = None,
                 ignore_invalid_stack=True, compare_memory=True, compare_registers=True, compare_side_effects=True,
                 compare_std_out=False, compare_std_err=False, use_unsat_core=True, simplify=False):
        """
        Compares a bundle of pre-patched states with a bundle of post-patched states.

        :param project.RunResult pre_patched: The pre-patched state bundle
        :param project.RunResult post_patched: The post-patched state bundle
        :param list[range] | None ignore_addrs: A list of addresses ranges to ignore when comparing memory.
        :param bool ignore_invalid_stack: If this flag is True, then memory differences in locations previously\
        occupied by the stack are ignored.
        :param bool compare_memory: If True, then the analysis will compare locations in the program memory.
        :param bool compare_registers: If True, then the analysis will compare registers used by the program.
        :param bool compare_side_effects: If True, then the analysis will compare side effects outputted by the program.
        :param bool compare_std_out: If True, then the analysis will save stdout written by the program in the results.\
        Note that angr currently concretizes values written to stdout, so these values will be binary strings.
        :param bool compare_std_err: If True, then the analysis will save stderr written by the program in the results.
        :param bool use_unsat_core: If this flag is True, then we will use unsat core optimization to speed up\
        comparison of pairs of states. This option may cause errors in Z3, so disable if this occurs.
        :param bool simplify: If this flag is True, then symbolic memory and register differences will be simplified\
        as much as possible. This flag is typically only necessary if you want to do some deep inspection of symbolic\
        contents. simplify can speed things down a lot, and symbolic expressions are usually very complex to the point\
        where they are not easily understandable. This is why in most scenarios the flag should be left as False.
        """

        if ignore_addrs is None:
            ignore_addrs = []

        self.pairs: dict[tuple[SimState, SimState], CompatiblePair] = dict()

        states_pre_patched: list[TerminalState] = (pre_patched.deadended + pre_patched.errored +
                                                   pre_patched.asserts_failed + pre_patched.postconditions_failed +
                                                   pre_patched.spinning)
        states_post_patched: list[TerminalState] = (post_patched.deadended + post_patched.errored +
                                                    post_patched.asserts_failed + post_patched.postconditions_failed +
                                                    post_patched.spinning)

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

        total_num_pairs = len(states_pre_patched) * len(states_post_patched)
        count = 0

        for (i, state_pre) in enumerate(states_pre_patched):
            for (j, state_post) in enumerate(states_post_patched):
                count += 1
                percentage = (count / total_num_pairs) * 100.0
                log.info("Comparing state pair %d of %d (%.0f%% complete)", count, total_num_pairs, percentage)

                if ignore_invalid_stack:
                    stack_change = state_pre.state.arch.stack_change
                    pair_ignore_addrs = ignore_addrs + [_invalid_stack_overlap(inv_addrs_pre_patched[i], inv_addrs_post_patched[j], stack_change)]
                else:
                    pair_ignore_addrs = ignore_addrs

                is_deadended_comparison = isinstance(state_pre, DeadendedState) and isinstance(state_post, DeadendedState)

                diff = memoized_diff.difference(
                    state_pre.state, state_post.state, pair_ignore_addrs,
                    compute_mem_diff=compare_memory if is_deadended_comparison else False,
                    compute_reg_diff=compare_registers if is_deadended_comparison else False,
                    compute_side_effect_diff=compare_side_effects if is_deadended_comparison else False,
                    use_unsat_core=use_unsat_core,
                    simplify=simplify
                )

                if diff is not None:
                    # These states are compatible, so remove them from the orphans sets
                    self.orphans_left.discard(state_pre)
                    self.orphans_right.discard(state_post)

                    mem_diff = diff.mem_diff
                    reg_diff = diff.reg_diff
                    side_effect_diff = diff.side_effect_diff

                    def get_ip_set(interval_dict, r: range):
                        # Query the interval dictionary for all entries in the desired range, then union
                        # all of those sets together
                        ip_sets = [s for (n, s) in interval_dict[P.closedopen(r.start, r.stop)].values()]
                        return frozenset().union(*ip_sets)

                    mem_diff_ip = {
                        addr_range: (get_ip_set(state_pre.mem_writes, addr_range), get_ip_set(state_post.mem_writes, addr_range))
                        for addr_range in mem_diff.keys()
                    }

                    comparison = CompatiblePair(state_pre, state_post, mem_diff, reg_diff, side_effect_diff,
                                                mem_diff_ip, compare_std_out, compare_std_err)
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
        Returns True when the two input states are compatible based on the pairs stored in this object, and False\
        otherwise.

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

    def verify(self, verification_assertion: Callable[[CompatiblePair], claripy.ast.Base | bool]) -> list[CompatiblePair]:
        """
        Determines what compatible state pairs are valid with respect to a verification assertion. Note that the\
        comparison results are verified with respect to the verification_assertion if the returned list is empty\
        (has length 0).

        :param Callable[[CompatiblePair], claripy.ast.Base | bool] verification_assertion: A function which takes in a\
        compatible pair and returns a claripy expression which must be satisfiable for all inputs while under the\
        joint constraints of the state pair. Alternatively the function can return a bool. If the return value\
        is False, this will be considered a verification failure. If the return value is True, this will be considered\
        a verification success.
        :return: A list of all compatible pairs for which there was a concrete input that caused the verification\
        assertion to fail.
        :rtype: list[CompatiblePair]
        """
        failure_list = []
        for ((state_left, state_right), pair_comp) in self.pairs.items():
            assertion = verification_assertion(pair_comp)

            if isinstance(assertion, bool):
                if assertion == False:
                    failure_list.append(pair_comp)
            else:
                joint_solver = claripy.Solver()
                joint_solver.add(state_left.solver.constraints)
                joint_solver.add(state_right.solver.constraints)

                try:
                    is_sat = joint_solver.satisfiable(extra_constraints=(~assertion,))
                except claripy.ClaripyZ3Error as err:
                    cozy.log.error("Unable to solve SMT formula when checking verification condition. The SMT solver returned unknown instead of SAT or UNSAT. We will assume that there is some way to falsify the verification condition.\nThe exception thrown was:\n{}", str(err))
                    is_sat = True
                except claripy.ClaripySolverInterruptError as err:
                    cozy.log.error("Unable to solve SMT formula when checking verification condition. The SMT solver was interrupted, most likely due to resource exhaustion. We will assume that there is some way to falsify the verification condition.\nThe exception thrown was:\n{}", str(err))
                    is_sat = True

                if is_sat:
                    failure_list.append(pair_comp)
        return failure_list

    def report(self, args: any, concrete_post_processor: Callable[[any], any] | None=None, num_examples: int=3) -> str:
        """
        Generates a human-readable report of the result object, saved as a string. This string is suitable for printing.

        :param any args: The symbolic/concolic arguments used during exeuction, here these args are concretized so that\
        we can give examples of concrete input.
        :param Callable[[any], any] | None concrete_post_processor: This function is used to post-process concretized\
        versions of args before they are added to the return string. Some examples of this function include converting\
        an integer to a negative number due to use of two's complement, or slicing off parts of the argument based on\
        another part of the input arguments.
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
                        if concrete_post_processor is not None:
                            input_args = concrete_post_processor(concrete_input.args)
                        else:
                            input_args = hexify(concrete_input.args)
                        output += "{}.\n".format(k + 1)
                        output += "\tInput arguments: {}\n".format(str(input_args))
                        if len(concrete_input.mem_diff) > 0:
                            output += "\tConcrete mem diff: {}\n".format(str(hexify(concrete_input.mem_diff)))
                        if len(concrete_input.reg_diff) > 0:
                            output += "\tConcrete reg diff: {}\n".format(str(hexify(concrete_input.reg_diff)))
                        def print_side_effects(side_effects: dict[str, list[ConcretePerformedSideEffect]]):
                            nonlocal output
                            for (channel, effects) in side_effects.items():
                                output += "Channel {}:\n".format(channel)
                                for eff in effects:
                                    output += str(eff.mapped_body) + "\n"
                        if len(concrete_input.left_side_effects) > 0:
                            output += "Prepatched side effects:\n"
                            print_side_effects(concrete_input.left_side_effects)
                        if len(concrete_input.right_side_effects) > 0:
                            output += "Postpatched side effects:\n"
                            print_side_effects(concrete_input.right_side_effects)

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
                if concrete_post_processor is not None:
                    input_args = concrete_post_processor(concrete_input.args)
                else:
                    input_args = hexify(concrete_input.args)
                output += "{}.\n".format(k + 1)
                output += "\tInput arguments: {}\n".format(str(input_args))
                if len(concrete_input.side_effects) > 0:
                    output += "Side effects:\n"
                    for (channel, effects) in concrete_input.side_effects.items():
                        output += "Channel {}:\n".format(channel)
                        for eff in effects:
                            output += str(eff.mapped_body) + "\n"

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
