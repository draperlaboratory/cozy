from angr import SimState
from angr.knowledge_plugins import Function, FunctionManager

from cozy.project import Session

class ArbitraryCandidate:
    """
    For use as the candidate heuristic in :py:meth:`cozy.exploration.ConcolicSim.generate_concrete`
    This heuristic will choose the next exploration candidate by popping the last element off the candidate's list.
    """
    def __call__(self, candidate_states: list[SimState]):
        return candidate_states.pop()

class BBTransitionCandidate:
    """
    For use as the candidate heuristic in :py:meth:`cozy.exploration.ConcolicSim.generate_concrete`
    This heuristic will select a candidate whose basic block history has been seen least frequently in the past. This
    class keeps an internal record of candidates it chose in the past to compute this metric.
    """
    def __init__(self, lookback: int=2):
        """
        :param int lookback: The number of basic blocks we should look back to when computing a candidate's transition\
        history. This should be a small integer, somewhere in the range 1 to 6. This number should in general only\
        be increased if the total number of states we search goes up. The candidate state with the most unique\
        transition history will be chosen by this heuristic.
        """
        self.transitions = {}
        self.lookback = lookback

    def __call__(self, candidate_states: list[SimState]):
        if len(candidate_states) == 0:
            raise ValueError("Cannot choose a candidate from a list of 0 length")
        min_count = None
        min_candidate = None
        min_transition = None
        # Find the candidate for which we have visited the least frequently among the past visits
        for candidate in candidate_states:
            def transition_tuple(history, n):
                if n == 0:
                    if history is None:
                        return None
                    else:
                        return history.addr
                else:
                    if history is None:
                        return (transition_tuple(None, n - 1), None)
                    else:
                        return (transition_tuple(history.parent, n - 1), history.addr)

            # Compute the transition history of this candidate state. The transition history
            # is a nested tuple containing the addresses of the last self.lookback basic blocks
            transition = (transition_tuple(candidate.history, self.lookback - 1), candidate.addr)

            count = self.transitions.get(transition, 0)
            if min_count is None or count < min_count:
                min_count = count
                min_candidate = candidate
                min_transition = transition

        self.transitions[min_transition] = min_count + 1
        candidate_states.remove(min_candidate)
        return min_candidate

class CompleteTermination:
    """
    This termination heuristic tells the concolic execution to explore until all states are deadended.
    """
    def __call__(self, simgr):
        return len(simgr.active) == 0

class CoverageTermination:
    """
    This termination heuristic tells the concolic execution to explore until a certain fraction of a
    function's basic blocks have been visited at least once.
    """
    def __init__(self, fun: Function, coverage_fraction: float=0.9):
        """
        :param Function fun: The function that we are seeking a specific coverage over.
        :param float coverage_fraction: A number in the range [0, 1] that determines what fraction of basic blocks need\
        to be visited before termination is reached.
        """
        self.block_addrs = fun.block_addrs_set
        self.prev_terminal_states = set()
        self.visited_blocks = set()
        self.coverage_fraction = coverage_fraction

    @staticmethod
    def from_session(sess: Session, coverage_fraction: float=0.9) -> 'CoverageTermination':
        """
        Constructs a CoverageTermination object from an unrun session.

        :param Session sess: The session which is set to call some specific function, but has not yet been run.
        :param float coverage_fraction: A number in the range [0, 1] that determines what fraction of basic blocks need\
        to be visited before termination is reached.
        """
        return CoverageTermination(sess.proj.cfg.kb.functions[sess.start_fun_addr], coverage_fraction=coverage_fraction)

    def __call__(self, simgr):
        for stash in [simgr.deadended, simgr.errored]:
            for state in stash:
                if state not in self.prev_terminal_states:
                    for addr in state.history.bbl_addrs:
                        if addr in self.block_addrs:
                            self.visited_blocks.add(addr)
                    self.prev_terminal_states.add(state)
        return ((len(self.visited_blocks) / len(self.block_addrs)) >= self.coverage_fraction)

class CyclomaticComplexityTermination:
    """
    This termination heuristic tells the concolic execution to explore until a certain number of terminated
    states are reached. If add_callees is False, then this value is equal to the cyclomatic complexity of the function.
    Otherwise, it is equal to the cyclomatic complexity of the function plus the cyclomatic complexity of all callees
    of the function (recursively).
    """

    def __init__(self, fun: Function, fun_manager: FunctionManager, add_callees=True, multiplier: int | float=1):
        """
        :param bool add_callees: If this parameter is True, the cyclomatic complexity of all functions deeper in the\
        call graph will be summed to determine the maximum number of states to explore. If False, the upper bound\
        will be the cyclomatic complexity of the session.
        :param int | float multiplier: The computed cyclomatic complexity sum will be multiplied by this value to\
        determine the number of states to explore
        """
        def rec_cyclomatic_complexity(addr, visited: frozenset[int]):
            if addr in visited:
                return 0
            else:
                if addr in fun_manager:
                    f = fun_manager[addr]
                    total = f.cyclomatic_complexity
                    visited_prime = visited.union({addr})
                    for bb_addr in f.get_call_sites():
                        calle_addr = f.get_call_target(bb_addr)
                        if calle_addr is not None:
                            total += rec_cyclomatic_complexity(calle_addr, visited_prime)
                    return total
                else:
                    return 0

        if add_callees:
            self.cyclomatic_complexity = rec_cyclomatic_complexity(fun.addr, frozenset())
        else:
            self.cyclomatic_complexity = fun.cyclomatic_complexity

        self.cyclomatic_complexity = int(multiplier * self.cyclomatic_complexity)

    @staticmethod
    def from_session(sess: Session, add_callees=True, multiplier: int | float=1) -> 'CyclomaticComplexityTermination':
        """
        Constructs an object from a session. The session must be started from a specific function.

        :param bool add_callees: If this parameter is True, the cyclomatic complexity of all functions deeper in the\
        call graph will be summed to determine the maximum number of states to explore. If False, the upper bound\
        will be the cyclomatic complexity of the session.
        :param int | float multiplier: The computed cyclomatic complexity sum will be multiplied by this value to\
        determine the number of states to explore
        """
        return CyclomaticComplexityTermination(sess.proj.cfg.kb.functions[sess.start_fun_addr],
                                               sess.proj.cfg.kb.functions, add_callees=add_callees,
                                               multiplier=multiplier)

    def __call__(self, simgr):
        return (len(simgr.deadended) + len(simgr.errored)) >= self.cyclomatic_complexity