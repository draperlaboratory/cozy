from angr import ExplorationTechnique, sim_options
import claripy

class ConcolicDeferred(ExplorationTechnique):
    def __init__(self, concrete_init: dict[claripy.BVS, claripy.BVV], deferred_stash="deferred",
                 check_only_recent_constraints=True):
        super().__init__()
        self.deferred_stash = deferred_stash
        self._set_replacement_dict(concrete_init)
        self.check_only_recent_constraints = check_only_recent_constraints

    @staticmethod
    def is_solution(constraints: list[claripy.ast.bool],
                    replacement_dict: dict[claripy.ASTCacheKey[claripy.BVS], claripy.BVV]) -> bool:
        return claripy.And(*constraints).replace_dict(replacement_dict).is_true()

    def _set_replacement_dict(self, concrete):
        self.concrete = concrete
        self.replacement_dict = {sym.cache_key: val for (sym, val) in concrete.items()}

    def set_concrete(self, simgr, concrete: dict[claripy.BVS, claripy.BVV]):
        self._set_replacement_dict(concrete)
        # If this path becomes too slow, instead of checking every state
        # in the deferred stash, we can follow execution from the initial states
        # This will probably not be a problem as is_solution should be pretty quick
        simgr.move(from_stash=self.deferred_stash, to_stash='active',
                   filter_func=lambda s: ConcolicDeferred.is_solution(s.solver.constraints, self.replacement_dict))

    def setup(self, simgr):
        if self.deferred_stash not in simgr.stashes:
            simgr.stashes[self.deferred_stash] = []
        # Disable default satisfiability checking since we are using a concrete
        # input during execution
        for s in simgr.active:
            s.options.add(sim_options.LAZY_SOLVES)

    def filter(self, simgr, state, **kwargs):
        if self.check_only_recent_constraints:
            constraints = [con.ast for con in state.history.recent_constraints]
        else:
            constraints = state.solver.constraints
        if ConcolicDeferred.is_solution(constraints, self.replacement_dict):
            return None
        else:
            return self.deferred_stash
