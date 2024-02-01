import claripy
from . import directive, claripy_ext
from .functools_ext import *

def _concretize(solver, state_bundle, n=1):
    def traverse(elem, bundle_symbols):
        if isinstance(elem, claripy.ast.Bits):
            if elem.symbolic:
                for leaf in elem.leaf_asts():
                    if leaf.symbolic:
                        bundle_symbols.add(leaf)
        return bundle_symbols

    extra_symbols = preorder_fold(state_bundle, traverse, set())

    model = claripy_ext.model(solver.constraints, extra_symbols=extra_symbols)
    replacement_dict = {sym.cache_key: val for (sym, val) in model.items()}

    def f(elem):
        if isinstance(elem, claripy.ast.Base):
            return elem.replace_dict(replacement_dict)
        else:
            return elem

    return [fmap(state_bundle, f)]

class CompatiblePairInput:
    """
    Stores information about the concretization of a compatible state pair.

    :ivar any args: The same Python datastructures as the arguments passed to concrete_examples, except that all claripy symbolic variables are replaced with concrete values.
    :ivar dict[range, tuple[int, int]] mem_diff: Concretized version of memory difference. Each key is a memory address range, and each value is a concretized version of the data stored at that location for the prepatched, postpatched runs.
    :ivar dict[str, tuple[int, int]] reg_diff: Concretized version of register difference. Each key is a register name, and each value is a concretized version of the data stored at that register for the prepatched, postpatched runs.
    :ivar list[tuple[directive.VirtualPrint, any]] left_vprints: Concretized versions of virtual prints made by the prepatched state.
    :ivar list[tuple[directive.VirtualPrint, any]] right_vprints: Concretized versions of virtual prints made by the postpatched state.
    """

    def __init__(self, args, mem_diff: dict[range, tuple[int, int]], reg_diff: dict[str, tuple[int, int]],
                 left_vprints: list[tuple[directive.VirtualPrint, any]], right_vprints: list[tuple[directive.VirtualPrint, any]]):
        self.args = args
        self.mem_diff = mem_diff
        self.reg_diff = reg_diff
        self.left_vprints = left_vprints
        self.right_vprints = right_vprints

class TerminalStateInput:
    """
    Stores information about the concretization of a TerminalState.

    :ivar any args: The same Python datastructures as the arguments passed to concrete_examples, except that all claripy symbolic variables are replaced with concrete values.
    :ivar list[tuple[directive.VirtualPrint, any]] vprints: Concretized virtual prints outputted by the singleton state.
    """
    def __init__(self, args, vprints: list[tuple[directive.VirtualPrint, any]]):
        self.args = args
        self.vprints = vprints