import typing
from enum import Enum

import angr
from angr import ExplorationTechnique, sim_options, SimulationManager
import claripy
from collections.abc import Callable

from claripy import UnsatError

from cozy import claripy_ext


# This module can be used independently from the rest of the cozy codebase. Perhaps someday the exploration
# techniques can be merged into the main angr codebase.

class ConcolicSim(ExplorationTechnique):
    """
    This class implements concolic execution without using an external emulator
    like QEMU or Unicorn. This class functions by storing a concrete assignment
    for each symbolic variable. When the state branches, the assignment is
    substituted into both children's constraints. If the substitution results
    in the constraints evaluating to false, that child is placed in the deferred
    stash. By querying the simulation manager's active stash length, we can
    tell when the concrete execution ends. When concrete execution ends, we
    can either choose a new concrete substitution ourselves and set it with
    the :py:meth:`ConcolicDeferred.set_concrete` method. Alternatively we
    can take one of the deferred states and generate and autogenerate a new
    concrete substitution by finding a satisfying assignment for that state's
    constraints.
    """
    def __init__(self, concrete_init: dict[claripy.BVS, claripy.BVV] | set[claripy.BVS] | frozenset[claripy.BVS],
                 deferred_stash="deferred",
                 check_only_recent_constraints=True):
        """
        ConcolicSim constructor

        :param dict[claripy.BVS, claripy.BVV] | set[claripy.BVS] | frozenset[claripy.BVS] concrete_init: Used to\
        initialize the concrete value. If this value is a substitution dictionary, then that dictionary is used as our\
        concrete input. If this value is a set or frozenset, then a substituting dictionary is autogenerated, subject\
        to the initial state's constraints.
        :param string deferred_stash: The name of the deferred stash
        :param bool check_only_recent_constraints: If this value is true, then whenever child states are created, only\
        the new constraints are checked with respect to the concrete substitution. Here we assume that the parent of\
        the child already satisfied the concrete input on a previous iteration, so it's safe to only check with respect\
        to the new constraints.
        """
        super().__init__()
        self.deferred_stash = deferred_stash
        if isinstance(concrete_init, dict):
            self._set_replacement_dict(concrete_init)
            self._symbols = None
        elif isinstance(concrete_init, set) or isinstance(concrete_init, frozenset):
            # Here the user has requested that we auto-generate the first concrete input
            # The actual generation of the replacement dictionary occurs in the setup()
            # method
            self.concrete = None
            self._replacement_dict = None
            self._symbols = concrete_init
        else:
            raise ValueError("Initial concrete values are not a dict, set, or frozenset")
        self.check_only_recent_constraints = check_only_recent_constraints

    def setup(self, simgr):
        # Setup the deferred stash
        if self.deferred_stash not in simgr.stashes:
            simgr.stashes[self.deferred_stash] = []
        if 'unsat' not in simgr.stashes:
            simgr.stashes['unsat'] = []
        # Disable default satisfiability checking since we are using a concrete
        # input during execution
        for s in simgr.active:
            s.options.add(sim_options.LAZY_SOLVES)
        if self._symbols is not None:
            self._generate_concrete(simgr, simgr.active, self._symbols)
            self._symbols = None

    def is_satisfied(self, constraints: list[claripy.ast.bool]) -> bool:
        """
        Substitutes the current concrete input into the constraints, and returns True if the constraints are True after
        the substitution is made.

        :param list[claripy.ast.bool] constraints: The constraints in which the concrete solution will be substituted.
        :rtype: bool
        :return: If the constraints are True after substitution, then True is returned. Otherwise returns False.
        """
        expr = claripy.replace_dict(claripy.And(*constraints), self._replacement_dict)
        if len(expr.variables) == 0:
            return expr.is_true()
        else:
            raise RuntimeError("Some symbols were unconstrained when checking for truthiness after substitution. Are you sure that all symbols are present in the set you passed to generate_concrete? Another likely cause of this error is a hook introducing a fresh symbolic variable")

    def _set_replacement_dict(self, concrete):
        self.concrete = concrete
        self._replacement_dict = {sym.hash(): val for (sym, val) in concrete.items()}

    def set_concrete(self, simgr, concrete: dict[typing.Union[claripy.BVS, claripy.FPS], typing.Union[claripy.BVV, claripy.FPV]]):
        """
        Sets the concrete input via a substitution dictionary. All the symbols used by the program should have concrete
        values provided for them. The active and deferred stash will be mutated to ensure that only states which
        are satisfied by the concrete substitution are active.

        :param dict[claripy.BVS, claripy.BVV] concrete: A dictionary mapping each symbol to its concrete value.
        """
        self._set_replacement_dict(concrete)
        simgr.move(from_stash='active', to_stash=self.deferred_stash)
        # If this path becomes too slow, instead of checking every state
        # in the deferred stash, we can follow execution from the initial states
        # This will probably not be a problem as is_solution should be pretty quick
        simgr.move(from_stash=self.deferred_stash, to_stash='active',
                   filter_func=lambda s: self.is_satisfied(s.solver.constraints))

    def _generate_concrete(self, simgr: angr.SimulationManager, from_stash: list[angr.SimState],
                           symbols: set[claripy.BVS] | frozenset[claripy.BVS],
                           candidate_heuristic: Callable[[list[angr.SimState]], angr.SimState] | None=None):
        while len(from_stash) > 0:
            if candidate_heuristic is None:
                candidate_state = from_stash.pop()
            else:
                candidate_state = candidate_heuristic(from_stash)
            try:
                models = claripy_ext.model(candidate_state.solver.constraints, extra_symbols=symbols, n=1)

                if len(models) > 0:
                    self._set_replacement_dict(models[0])
                    simgr.active.append(candidate_state)
                    return
                else:
                    simgr.unsat.append(candidate_state)
            except UnsatError:
                simgr.unsat.append(candidate_state)

    def generate_concrete(self, simgr: angr.SimulationManager, symbols: set[claripy.BVS] | frozenset[claripy.BVS],
                          candidate_heuristic: Callable[[list[angr.SimState]], angr.SimState] | None=None):
        """
        Autogenerates a new concrete input by choosing a deferred state and finding a satisfying assignment
        with respect to that state's constraints. The symbols provided will be used to internally generate
        a substitution dictionary. The candidate_heuristic is used to choose a state from the current stash
        of deferred states. If no heuristic is provided, the last state in the deferred stash will be chosen next.
        If there are any active states in the simulation manager, a ValueError will be thrown.

        :param angr.SimulationManager simgr: The simulation manager
        :param set[claripy.BVS] | frozenset[claripy.BVS] symbols: The symbols that we will generate a substitution for.
        :param Callable[[list[angr.SimState]], angr.SimState] | None candidate_heuristic: The heuristic that should be\
        used to choose the deferred state that should be explored further. Note that this function should mutate its\
        input list (ie, remove the desired state), and return that desired state.
        """
        if len(simgr.active) > 0:
            raise ValueError("Concrete input can only be set when there are 0 active states.")
        self._generate_concrete(simgr, simgr.stashes[self.deferred_stash], symbols,
                                candidate_heuristic=candidate_heuristic)

    def filter(self, simgr, state, **kwargs):
        if self.check_only_recent_constraints:
            constraints = [con.ast for con in state.history.recent_constraints]
        else:
            constraints = state.solver.constraints
        if self.is_satisfied(constraints):
            return None
        else:
            return self.deferred_stash

class _ExploreMode(Enum):
    EXPLORE_LEFT = 0
    EXPLORE_RIGHT = 1

class JointConcolicSim:
    """
    Jointly runs two SimulationManager objects by concretizing symbols, then running the left and right simulations
    with the same concrete input. This joint simulator alternates between the left and right simulations
    when generating new concrete inputs.
    """
    def __init__(self, simgr_left: SimulationManager, simgr_right: SimulationManager,
                 symbols: set[claripy.BVS] | frozenset[claripy.BVS],
                 left_explorer: ConcolicSim, right_explorer: ConcolicSim,
                 candidate_heuristic_left: Callable[[list[angr.SimState]], angr.SimState] | None = None,
                 candidate_heuristic_right: Callable[[list[angr.SimState]], angr.SimState] | None = None):
        """
        :param SimulationManager simgr_left: The first simulation manager to run in concolic execution
        :param SimulationManager simgr_right: The second simulation manager to run in concolic execution.
        :param ConcolicSim left_explorer: The first exploration method to use for concolic execution. Note that\
        this exploration technique will be attached to the left simulation manager.
        :param ConcolicSim right_explorer: The second exploration method to use for concolic execution. Note that\
        this exploration technique will be attached to the right simulation manager.
        :param Callable[[list[angr.SimState]], angr.SimState] | None candidate_heuristic_left: The heuristic that\
        should be used to choose the deferred state that should be explored further. Note that this function should\
        mutate its input list (ie, remove the desired state), and return that desired state. Note that some\
        pre-made candidate heuristic techniques can be found in the :py:mod:`cozy.concolic.heuristics` module.
        :param Callable[[list[angr.SimState]], angr.SimState] | None candidate_heuristic_right: The heuristic that\
        should be used to choose the deferred state that should be explored further. Note that this function should\
        mutate its input list (ie, remove the desired state), and return that desired state. Note that some\
        pre-made candidate heuristic techniques can be found in the :py:mod:`cozy.concolic.heuristics` module.
        """
        self.simgr_left = simgr_left
        self.simgr_right = simgr_right
        self.symbols = symbols
        self.explore_mode = _ExploreMode.EXPLORE_LEFT
        self.left_explorer = left_explorer
        self.right_explorer = right_explorer
        left_explorer._symbols = None
        right_explorer._symbols = None
        self.candidate_heuristic_left = candidate_heuristic_left
        self.candidate_heuristic_right = candidate_heuristic_right
        self._generate_concrete(simgr_left.active, simgr_right.active)
        self.simgr_left.use_technique(self.left_explorer)
        self.simgr_right.use_technique(self.right_explorer)

    def _swap_explore_mode(self):
        if self.explore_mode == _ExploreMode.EXPLORE_LEFT:
            self.explore_mode = _ExploreMode.EXPLORE_RIGHT
        else:
            self.explore_mode = _ExploreMode.EXPLORE_LEFT

    def _generate_concrete(self, from_stash_left, from_stash_right):
        if self.explore_mode == _ExploreMode.EXPLORE_LEFT:
            primary_explorer = self.left_explorer
            primary_simgr = self.simgr_left
            primary_from_stash = from_stash_left
            primary_heuristic = self.candidate_heuristic_left
            secondary_explorer = self.right_explorer
            secondary_simgr = self.simgr_right
        else:
            primary_explorer = self.right_explorer
            primary_simgr = self.simgr_right
            primary_from_stash = from_stash_right
            primary_heuristic = self.candidate_heuristic_right
            secondary_explorer = self.left_explorer
            secondary_simgr = self.simgr_left

        primary_explorer._generate_concrete(primary_simgr, primary_from_stash, self.symbols,
                                            candidate_heuristic=primary_heuristic)
        secondary_explorer.set_concrete(secondary_simgr, primary_explorer.concrete)

    def explore(self,
                explore_fun_left: Callable[[SimulationManager], None] | None = None,
                explore_fun_right: Callable[[SimulationManager], None] | None = None,
                termination_fun_left: Callable[[SimulationManager], bool] | None = None,
                termination_fun_right: Callable[[SimulationManager], bool] | None = None,
                loop_bound_left: int | None=None, loop_bound_right: int | None=None) -> None:
        """
        Explores the simulations given in the left and right simulation manager.

        :param Callable[[SimulationManager], None] | None explore_fun_left: If this parameter is not None, then\
        instead of :py:meth:`SimulationManager.explore` being called to do the exploration, we call explore_fun_left\
        instead.
        :param Callable[[SimulationManager], None] | None explore_fun_right: If this parameter is not None, then\
        instead of :py:meth:`SimulationManager.explore` being called to do the exploration, we call explore_fun_right\
        instead.
        :param Callable[[SimulationManager], bool] | None termination_fun_left: Every time we finish exploring one\
        concrete input, this function is called to determine if the exploration should terminate. If both termination\
        functions return True, then exploration is halted and this function returns. If this parameter is None, then\
        the left simulation manager will terminate only when no further exploration is possible (ie, execution is\
        complete). Pre-made termination functions can be found in the :py:mod:`cozy.concolic.heuristics` module.
        :param Callable[[SimulationManager], bool] | None termination_fun_right: Every time we finish exploring one\
        concrete input, this function is called to determine if the exploration should terminate. If both termination\
        functions return True, then exploration is halted and this function returns. If this parameter is None, then\
        the right simulation manager will terminate only when no further exploration is possible (ie, execution is\
        complete). Pre-made termination functions can be found in the :py:mod:`cozy.concolic.heuristics` module.
        :param int | None loop_bound_left: Sets an upper bound on loop iteration count for the left session. Useful for\
        programs with non-terminating loops.
        :param int | None loop_bound_right: Sets an upper bound on loop iteration count for the right session. Useful\
        for programs with non-terminating loops.
        :return: None
        :rtype: None
        """

        if isinstance(loop_bound_left, int):
            self.simgr_left.use_technique(angr.exploration_techniques.LocalLoopSeer(bound=loop_bound_left))
        if isinstance(loop_bound_right, int):
            self.simgr_right.use_technique(angr.exploration_techniques.LocalLoopSeer(bound=loop_bound_right))

        while len(self.simgr_left.active) > 0 or len(self.simgr_right.active) > 0:
            if (termination_fun_left is not None and termination_fun_right is not None and
                    (len(self.simgr_left.active) == 0 or termination_fun_left(self.simgr_left)) and
                    (len(self.simgr_right.active) == 0 or termination_fun_right(self.simgr_right))):
                return

            if explore_fun_left is None:
                self.simgr_left.explore()
            else:
                explore_fun_left(self.simgr_left)
            if explore_fun_right is None:
                self.simgr_right.explore()
            else:
                explore_fun_right(self.simgr_right)

            def swap_and_generate():
                self._swap_explore_mode()
                self._generate_concrete(self.simgr_left.stashes[self.left_explorer.deferred_stash],
                                        self.simgr_right.stashes[self.right_explorer.deferred_stash])
            swap_and_generate()
            if len(self.simgr_left.active) == 0 and len(self.simgr_right.active) == 0:
                swap_and_generate()
