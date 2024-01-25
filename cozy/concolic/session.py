from collections.abc import Callable

import angr, claripy
from angr.sim_manager import SimulationManager
from .exploration import JointConcolicSim, ConcolicSim
from ..session import Session, RunResult

class JointConcolicSession:
    def __init__(self, sess_left: Session, sess_right: Session,
                 candidate_heuristic_left: Callable[[list[angr.SimState]], angr.SimState] | None = None,
                 candidate_heuristic_right: Callable[[list[angr.SimState]], angr.SimState] | None = None,
                 termination_heuristic_left: Callable[[SimulationManager], bool] | None = None,
                 termination_heuristic_right: Callable[[SimulationManager], bool] | None = None):
        self.sess_left = sess_left
        self.sess_right = sess_right

        self.candidate_heuristic_left = candidate_heuristic_left
        self.candidate_heuristic_right = candidate_heuristic_right

        self.termination_heuristic_left = termination_heuristic_left
        self.termination_heuristic_right = termination_heuristic_right

    def run(self, args_left, args_right, symbols: set[claripy.BVS] | frozenset[claripy.BVS],
            cache_intermediate_states: bool=False, cache_constraints: bool=True,
            ret_addr_left: int | None=None, ret_addr_right: int | None = None) -> tuple[RunResult, RunResult]:

        simgr_left = self.sess_left._call(args_left, cache_intermediate_states=cache_intermediate_states,
                                          cache_constraints=cache_constraints, ret_addr=ret_addr_left)
        simgr_right = self.sess_right._call(args_right, cache_intermediate_states=cache_intermediate_states,
                                           cache_constraints=cache_constraints, ret_addr=ret_addr_right)

        sess_exploration_left = self.sess_left._session_exploration(cache_intermediate_states=cache_intermediate_states,
                                                                    cache_constraints=cache_constraints)
        sess_exploration_right = self.sess_right._session_exploration(cache_intermediate_states==cache_intermediate_states,
                                                                      cache_constraints=cache_constraints)

        concolic_explorer_left = ConcolicSim(symbols)
        concolic_explorer_right = ConcolicSim(symbols)

        jconcolic_sim = JointConcolicSim(simgr_left, simgr_right, symbols, concolic_explorer_left, concolic_explorer_right,
                                         candidate_heuristic_left=self.candidate_heuristic_left,
                                         candidate_heuristic_right=self.candidate_heuristic_right)

        jconcolic_sim.explore(explore_fun_left=sess_exploration_left.explore,
                              explore_fun_right=sess_exploration_right.explore,
                              termination_fun_left=self.termination_heuristic_left,
                              termination_fun_right=self.termination_heuristic_right)

        return (self.sess_left._run_result(simgr_left, sess_exploration_left),
                self.sess_right._run_result(simgr_right, sess_exploration_right))