import claripy

from . import primitives


# Functions that should be included in claripy, but aren't

# Constrained a symbolic integer x to fall in a range [low, high) where low and high are Python integers
def twos_comp_range_constraint(x, low: int, high: int):
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

# Simplifies a claripy AST expression, given some knowledge base (kb) of information
def simplify_kb(expr, kb) -> claripy.ast.Base:
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