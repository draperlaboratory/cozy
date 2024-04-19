import typing
import cozy
import claripy

from . import primitives


# Functions that should be included in claripy, but aren't

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

def get_symbol_name(sym):
    return sym.args[0]

def model(constraints,
          extra_symbols: set[typing.Union[claripy.BVS, claripy.FPS]] | frozenset[typing.Union[claripy.BVS, claripy.FPS]]=frozenset(),
          n=1,
          **kwargs) -> list[dict[typing.Union[claripy.BVS, claripy.FPS], typing.Union[claripy.BVV, claripy.FPV]]]:
    # Computes at most n different satisfying assignments for a set of constraints
    solver = claripy.Solver()
    solver.add(constraints)
    generated_models = []
    while len(generated_models) < n:
        try:
            is_sat = solver.satisfiable(**kwargs)
        except claripy.ClaripyZ3Error as err:
            cozy.log.error("Unable to generate model for SMT formula. The SMT solver returned unknown instead of SAT or UNSAT.\nThe exception thrown was:\n{}", str(err))
            return generated_models
        except claripy.ClaripySolverInterruptError as err:
            cozy.log.error("Unable to generate model for SMT formula. The SMT solver was interrupted, most likely due to resource exhaustion.\nThe exception thrown was:\n{}", str(err))
            return generated_models

        if is_sat:
            models = list(solver._models)

            ret = dict()

            def zero(sym):
                if sym.op == "BVS":
                    return claripy.BVV(0, sym.length)
                elif sym.op == "FPS":
                    return claripy.FPV(0.0, sym.sort)
                elif sym.op == "BoolS":
                    return claripy.BoolV(False)
                else:
                    raise ValueError("Unsupported op")

            def value(sym, v):
                if sym.op == "BVS":
                    return claripy.BVV(v, sym.length)
                elif sym.op == "FPS":
                    return claripy.FPV(v, sym.sort)
                elif sym.op == "BoolS":
                    return claripy.BoolV(v)
                else:
                    raise ValueError("Unsupported op")

            if len(models) > 0:
                # m maps symbol names to either integers or floats. We want symbols to map
                # to BVV or FPS, so we need to do that conversion here
                m = models[0].model
                for c in solver.constraints:
                    for leaf in c.leaf_asts():
                        if leaf.symbolic:
                            leaf_name = get_symbol_name(leaf)
                            if leaf_name in m:
                                ret[leaf] = value(leaf, m[leaf_name])
                            else:
                                ret[leaf] = zero(leaf)
            else:
                raise ValueError("Failed to generate a model for a satisfiable solution")

            # Set any symbols not in the model to 0
            for extra in extra_symbols:
                if extra not in ret:
                    ret[extra] = zero(extra)

            generated_models.append(ret)

            if len(generated_models) < n:
                # We need to find a solution that is different from the model we just found in at least one variable
                solver.add(claripy.Or(*[sym != val for (sym, val) in ret.items()]))
                # We don't want to accumulate models between calls to .satisfiable(), so clear out the model we
                # just found here
                solver._models.clear()
        else:
            return generated_models
    return generated_models