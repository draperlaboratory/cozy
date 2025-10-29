import claripy
from . import directive, claripy_ext
from .functools_ext import *
from .nested_dict import NestedDict
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
        elif isinstance(elem, NestedDict):
            preorder_fold(elem.data, traverse, bundle_symbols)
        return bundle_symbols

    # First, walk over the state bundle to find all symbols contained within the nested data structure
    extra_symbols = preorder_fold(state_bundle, traverse, set())

    # Generate up to n models, finding the substitutions for all the symbols
    # Each model maps each symbol found in the previous step to a concrete value
    models = claripy_ext.model(solver.constraints, extra_symbols=extra_symbols, n=n)
    ret = []
    for model in models:
        replacement_dict = {sym.hash(): val for (sym, val) in model.items()}

        def f(elem):
            if isinstance(elem, claripy.ast.Base):
                return claripy.replace_dict(elem, replacement_dict)
            elif isinstance(elem, PerformedSideEffect):
                return ConcretePerformedSideEffect(elem, elem.state_history, fmap(elem.body, f), concrete_post_processor=elem.concrete_post_processor, label=elem.label)
            elif isinstance(elem, NestedDict):
                return elem.map(f)
            else:
                return elem

        ret.append(fmap(state_bundle, f))

    return ret

class CompatiblePairInput:
    """
    Stores information about the concretization of a compatible state pair.

    :ivar any args: The same Python datastructures as the arguments passed to concrete_examples, except that all claripy symbolic variables are replaced with concrete values.
    :ivar dict[range, tuple[claripy.ast.Bits, claripy.ast.Bits]] mem_diff: Concretized version of memory difference. Each key is a memory address range, and each value is a concretized version of the data stored at that location for the prepatched, postpatched runs.
    :ivar dict[str, tuple[claripy.ast.Bits, claripy.ast.Bits]] reg_diff: Concretized version of register difference. Each key is a register name, and each value is a concretized version of the data stored at that register for the prepatched, postpatched runs.
    :ivar dict[str, list[ConcretePerformedSideEffect]] left_side_effects: Concretized versions of side effects made by the prepatched state.
    :ivar dict[str, list[ConcretePerformedSideEffect]] right_side_effects: Concretized versions of side_effects made by the postpatched state.
    :ivar NestedDict[claripy.ast.Base] | None left_annotation: Concretized version of the memory annotated with :py:meth:`cozy.session.Session.annotate_memory` for the first program.
    :ivar NestedDict[claripy.ast.Base] | None right_annotation: Concretized version of the memory annotated with :py:meth:`cozy.session.Session.annotate_memory` for the second program.
    :ivar NestedDict[claripy.ast.Base] | None left_ret_annotation: Concretized version of the annotated return results for the first program. These annotations were created via :py:meth:`cozy.session.Session.annotate_return`.
    :ivar NestedDict[claripy.ast.Base] | None right_ret_annotation: Concretized version of the annotated return results for the second program. These annotations were created via :py:meth:`cozy.session.Session.annotate_return`
    """
    def __init__(self,
                 args,
                 mem_diff: dict[range, tuple[claripy.ast.Bits, claripy.ast.Bits]],
                 reg_diff: dict[str, tuple[claripy.ast.Bits, claripy.ast.Bits]],
                 left_side_effects: dict[str, list[ConcretePerformedSideEffect]],
                 right_side_effects: dict[str, list[ConcretePerformedSideEffect]],
                 left_annotation: NestedDict[claripy.ast.Base],
                 right_annotation: NestedDict[claripy.ast.Base],
                 left_ret_annotation: NestedDict[claripy.ast.Base],
                 right_ret_annotation: NestedDict[claripy.ast.Base]):
        self.args = args
        self.mem_diff = mem_diff
        self.reg_diff = reg_diff
        self.left_side_effects = left_side_effects
        self.right_side_effects = right_side_effects
        self.left_annotation = left_annotation
        self.right_annotation = right_annotation
        self.left_ret_annotation = left_ret_annotation
        self.right_ret_annotation = right_ret_annotation

class TerminalStateInput:
    """
    Stores information about the concretization of a TerminalState.

    :ivar any args: The same Python datastructures as the arguments passed to concrete_examples, except that all claripy symbolic variables are replaced with concrete values.
    :ivar dict[str, list[PerformedSideEffect]] side_effects: Concretized side effects outputted by the singleton state.
    """
    def __init__(self, args, side_effects: dict[str, list[ConcretePerformedSideEffect]]):
        self.args = args
        self.side_effects = side_effects