import claripy
from . import directive, claripy_ext
from .functools_ext import *
from .side_effect import PerformedSideEffect, ConcretePerformedSideEffect


def _concretize(solver, state_bundle, n=1):
    def traverse(elem, bundle_symbols):
        if isinstance(elem, claripy.ast.Bits):
            if elem.symbolic:
                for leaf in elem.leaf_asts():
                    if leaf.symbolic:
                        bundle_symbols.add(leaf)
        elif isinstance(elem, PerformedSideEffect):
            preorder_fold(elem.body, traverse, bundle_symbols)
        return bundle_symbols

    extra_symbols = preorder_fold(state_bundle, traverse, set())

    models = claripy_ext.model(solver.constraints, extra_symbols=extra_symbols, n=n)
    ret = []
    for model in models:
        replacement_dict = {sym.cache_key: val for (sym, val) in model.items()}

        def f(elem):
            if isinstance(elem, claripy.ast.Base):
                return elem.replace_dict(replacement_dict)
            elif isinstance(elem, PerformedSideEffect):
                return ConcretePerformedSideEffect(elem, elem.state_history, fmap(elem.body, f), concrete_post_processor=elem.concrete_post_processor, label=elem.label)
            else:
                return elem

        ret.append(fmap(state_bundle, f))

    return ret

class CompatiblePairInput:
    """
    Stores information about the concretization of a compatible state pair.

    :ivar any args: The same Python datastructures as the arguments passed to concrete_examples, except that all claripy symbolic variables are replaced with concrete values.
    :ivar dict[range, tuple[int, int]] mem_diff: Concretized version of memory difference. Each key is a memory address range, and each value is a concretized version of the data stored at that location for the prepatched, postpatched runs.
    :ivar dict[str, tuple[int, int]] reg_diff: Concretized version of register difference. Each key is a register name, and each value is a concretized version of the data stored at that register for the prepatched, postpatched runs.
    :ivar dict[str, list[ConcretePerformedSideEffect]] left_side_effects: Concretized versions of side effects made by the prepatched state.
    :ivar dict[str, list[ConcretePerformedSideEffect]] right_side_effects: Concretized versions of side_effects made by the postpatched state.
    """

    def __init__(self, args, mem_diff: dict[range, tuple[int, int]], reg_diff: dict[str, tuple[int, int]],
                 left_side_effects: dict[str, list[ConcretePerformedSideEffect]], right_side_effects: dict[str, list[ConcretePerformedSideEffect]]):
        self.args = args
        self.mem_diff = mem_diff
        self.reg_diff = reg_diff
        self.left_side_effects = left_side_effects
        self.right_side_effects = right_side_effects

class TerminalStateInput:
    """
    Stores information about the concretization of a TerminalState.

    :ivar any args: The same Python datastructures as the arguments passed to concrete_examples, except that all claripy symbolic variables are replaced with concrete values.
    :ivar dict[str, list[PerformedSideEffect]] side_effects: Concretized side effects outputted by the singleton state.
    """
    def __init__(self, args, side_effects: dict[str, list[ConcretePerformedSideEffect]]):
        self.args = args
        self.side_effects = side_effects