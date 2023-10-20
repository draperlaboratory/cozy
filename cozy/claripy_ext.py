import claripy

from . import primitives


# Functions that should be included in claripy, but aren't

def twos_comp_range_constraint(x: claripy.ast.bits, low: int, high: int) -> claripy.ast.Bool:
    """
    Generates a constraint which bounds the input argument in range [low, high), assuming a two's complement representation.

    :param clairpy.ast.bits x: The bits to constrain. Typically, this is a symbolic bitvector.
    :param int low: The lower bound on the range. This number may be negative.
    :param int high: The upper bound on the range.
    """
    num_bits = x.length
    sign_bit = x[(num_bits - 1):(num_bits - 1)]
    if low >= 0 and high >= 0:
        return ((sign_bit == 0) & (low <= x) & (x < high))
    elif low < 0 and high > 0:
        return (((sign_bit == 1) & (primitives.to_twos_comp(low, num_bits) <= x)) | ((sign_bit == 0) & (x < high)))
    elif low < 0 and high < 0:
        return ((sign_bit == 1) & (primitives.to_twos_comp(low, num_bits) <= x) & (x < primitives.to_twos_comp(high, num_bits)))
    else:
        raise ValueError("low was greater than high")

def simplify_kb(expr: claripy.ast.bits, kb: claripy.ast.Bool) -> claripy.ast.bits:
    """
    Simplifies a claripy AST expression, given some knowledge base (kb) of information

    :param claripy.ast.bits expr: The expression to simplify
    :param claripy.ast.Bool kb: The knowledge base which is used to simplify the expr. This is typically a series of equalities conjoined together.
    :return: A simplified version of the input expression, or the original expression if no simplification occurred.
    :rtype: claripy.ast.bits
    """
    if not expr.symbolic:
        return expr
    else:
        v = claripy.BVS("simp_kb_var", expr.length)
        solver = claripy.Solver()
        solver.add(kb)
        solver.add(v == expr)
        solver.simplify()
        for c in solver.constraints:
            if c.op == "__eq__" and len(c.args) == 2:
                (lhs, rhs) = c.args
                if lhs is v:
                    simplified_expr = rhs
                elif rhs is v:
                    simplified_expr = lhs
                else:
                    continue
                return simplified_expr
        return expr