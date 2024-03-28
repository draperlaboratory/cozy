from collections.abc import Callable

import angr, claripy
from angr.sim_manager import SimulationManager
from .exploration import JointConcolicSim, ConcolicSim
from ..session import Session, RunResult

class JointConcolicSession:
    """
    This class is used for jointly running two sessions using concolic execution. The sessions need to be run
    jointly because the concrete values generated during concolic execution need to be fed to both programs.
    """

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

    def run(self, args_left: list[claripy.ast.bits], args_right: list[claripy.ast.bits],
            symbols: set[claripy.BVS] | frozenset[claripy.BVS],
            cache_intermediate_info: bool=True,
            ret_addr_left: int | None=None, ret_addr_right: int | None = None,
            loop_bound_left: int | None=None, loop_bound_right: int | None=None) -> tuple[RunResult, RunResult]:
        """
        Jointly run two sessions.

        :param list[claripy.ast.bits] args_left: The arguments to pass to the left session.
        :param list[claripy.ast.bits] args_right: The arguments to pass to the right session.
        :param set[claripy.BVS] | frozenset[claripy.BVS] symbols: All symbolic values used in the two sessions. These\
        symbols may be passed as arguments, or may have been pre-stored in the memory of the session before this\
        method was called. This set is required during the concretization step where we need to generate concrete\
        values for all symbolic values in the program.
        :param bool cache_intermediate_info: If this flag is True, then information about intermediate states will be
        cached. This is required for dumping the execution graph which is used in visualization.
        :param int | None ret_addr_left: What address to return to if calling as a function
        :param int | None ret_addr_right: What address to return to if calling as a function
        :param int | None loop_bound_left: Sets an upper bound on loop iteration count for the left session. Useful\
        for programs with non-terminating loops.
        :param int | None loop_bound_right: Sets an upper bound on loop iteration count for the right session. Useful\
        for programs with non-terminating loops.

        :return: The result of running the two sessions, where the first element of the return tuple being the left\
        session's result, and the second element being the right session's result.
        :rtype: tuple[RunResult, RunResult]
        """

        simgr_left = self.sess_left._call(args_left, cache_intermediate_info=cache_intermediate_info,
                                          ret_addr=ret_addr_left)
        simgr_right = self.sess_right._call(args_right, cache_intermediate_info=cache_intermediate_info,
                                            ret_addr=ret_addr_right)

        sess_exploration_left = self.sess_left._session_exploration(cache_intermediate_info=cache_intermediate_info)
        sess_exploration_right = self.sess_right._session_exploration(cache_intermediate_info=cache_intermediate_info)

        concolic_explorer_left = ConcolicSim(symbols)
        concolic_explorer_right = ConcolicSim(symbols)

        jconcolic_sim = JointConcolicSim(simgr_left, simgr_right, symbols, concolic_explorer_left, concolic_explorer_right,
                                         candidate_heuristic_left=self.candidate_heuristic_left,
                                         candidate_heuristic_right=self.candidate_heuristic_right)

        jconcolic_sim.explore(explore_fun_left=sess_exploration_left.explore,
                              explore_fun_right=sess_exploration_right.explore,
                              termination_fun_left=self.termination_heuristic_left,
                              termination_fun_right=self.termination_heuristic_right,
                              loop_bound_left=loop_bound_left, loop_bound_right=loop_bound_right)

        return (self.sess_left._run_result(simgr_left, sess_exploration_left),
                self.sess_right._run_result(simgr_right, sess_exploration_right))