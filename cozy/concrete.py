import claripy
from . import directive
from .functools_ext import *

def _concretize(solver, state_bundle, n=1):
    def f(elem, accum):
        if isinstance(elem, claripy.ast.Base):
            accum.append(elem)
        return accum
    # eval_lst will be a list, where the order of the elements is determined by
    # the order they are visited in a preorder traversal of the Python datastructures
    # The elements in question are claripy AST nodes that we are going to evaluate
    eval_lst = preorder_fold(state_bundle, f, [])

    # This is a list of concrete examples
    concrete_vals_lst = solver.batch_eval(eval_lst, n)

    ret = []

    # Foreach concrete example
    for concrete_vals in concrete_vals_lst:
        # Map the original datastructure so that claripy.ast.Base elements are replaced
        # with their concrete values.
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