from angr import SimState, SimError
import sys

import portion as P

from angr.sim_manager import ErrorRecord

from . import side_effect
from .concrete import _concretize, TerminalStateInput
import claripy
from .directive import Assert, VirtualPrint, Postcondition
from .side_effect import PerformedSideEffect


class TerminalState:
    """
    Stores information pertaining specifically to a single SimState.

    :ivar SimState state: The state we are storing information about.
    :ivar int state_id: The index of this particular state in the corresponding list in RunResult. Note that errored states have separate state_ids from deadended states. Therefore a particular input state here is uniquely identified by the pair (state_id, state_tag), not just state_id by itself.
    :ivar str state_type_str: A string representation of the state's type
    """
    def __init__(self, state: SimState, state_id: int, state_type_str: str):
        self.state = state
        self.state_id = state_id
        self._std_out = None
        self._std_err = None
        self.state_type_str = state_type_str

    @property
    def std_out(self) -> bytes:
        """
        The data that has been written to stdout when the program is in this state.

        :getter: The data written to stdout
        :type: bytes
        """
        if self._std_out is None:
            stdout_fileno = sys.stdout.fileno()
            self._std_out = self.state.posix.dumps(stdout_fileno)
        return self._std_out

    @property
    def std_err(self) -> bytes:
        """
        The data that has been written to stderr when the program is in this state.

        :getter: The data written to stderr
        :type: bytes
        """
        if self._std_err is None:
            stderr_fileno = sys.stderr.fileno()
            self._std_err = self.state.posix.dumps(stderr_fileno)
        return self._std_err

    @property
    def side_effects(self) -> dict[str, list[PerformedSideEffect]]:
        return side_effect.get_effects(self.state)

    @property
    def virtual_prints(self) -> list[PerformedSideEffect]:
        """
        Returns the output of the virtual prints that occurred while reaching this state.

        :getter: A list of VirtualPrint directives, along with the values they produced.
        :type: list[tuple[VirtualPrint, claripy.ast.Base]]
        """
        return side_effect.get_channel(self.state, 'virtual_prints')

    @property
    def mem_writes(self) -> P.IntervalDict:
        """
        The memory writes that occurred while reaching this state.

        :getter: An interval dictionary, with the keys being ranges and the values being tuple[int, frozenset[int]]. The first element of the tuple is a unique placeholder, the second element of the tuple are the possible instruction pointer values that wrote to this memory.
        :type: P.IntervalDict
        """
        if 'mem_writes' in self.state.globals:
            return self.state.globals['mem_writes']
        else:
            return P.IntervalDict()

    @property
    def malloced_names(self) -> P.IntervalDict:
        if 'malloced_names' in self.state.globals:
            return self.state.globals['malloced_names']
        else:
            return P.IntervalDict()

    def concrete_examples(self, args: any, num_examples=3) -> list[TerminalStateInput]:
        """
        Concretizes the arguments used to put the program in this singleton state.

        :param any args: The input arguments to concretize. This argument may be a Python datastructure, the concretizer will make a deep copy with claripy symbolic variables replaced with concrete values.
        :param int num_examples: The maximum number of concrete examples to generate for this singleton state.
        :return: A list of concrete inputs that satisfies the constraints attached to the state.
        :rtype: list[TerminalStateInput]
        """
        state_bundle = (args, self.virtual_prints)
        solver = claripy.Solver()
        solver.add(self.state.solver.constraints)
        concrete_results = _concretize(solver, state_bundle, n=num_examples)
        return [TerminalStateInput(conc_args, conc_vprints) for (conc_args, conc_vprints) in concrete_results]

class DeadendedState(TerminalState):
    """
    This class is used to indicate that execution terminated normally in the contained state.
    """
    def __init__(self, state: SimState, state_id: int):
        """
        Constructor for DeadendedState

        :ivar SimState state: The state that terminated normally.
        :ivar int state_id: The identifer of the state, determined by its position in the list :py:obj:`cozy.project.RunResult.deadended`
        """
        super().__init__(state, state_id, "DEADENDED_STATE")

class SpinningState(TerminalState):
    """
    This class is used to indicate that the contained state was killed by the LocalLoopSeer, indicating that an upper
    bound on number of loop iterations was reached.
    """
    def __init__(self, state: SimState, state_id: int):
        """
        Constructor for SpinningState

        :ivar SimState state: The state that was spinning
        :ivar int state_id: The identifer of the state, determined by its position in the list :py:obj:`cozy.project.RunResult.spinning`
        """
        super().__init__(state, state_id, "SPINNING_STATE")

class AssertFailedState(TerminalState):
    """
    This class is used to indicate that execution failed due to an :py:class:`~cozy.directive.Assert` being satisfiable.

    :ivar Assert assertion: The assertion that was triggered.
    :ivar claripy.ast.bool cond: The condition that caused the assertion to trigger
    """
    def __init__(self, assertion: Assert, cond: claripy.ast.bool, failure_state: SimState, state_id: int):
        """
        Constructor for AssertFailedState

        :param Assert assertion: The assertion that was triggered.
        :param claripy.ast.bool: The condition which if falsified will trigger the assertion.
        :param SimState failure_state: The state that was created to test the assertion.
        :param int state_id: The identifier of the state, determined by its position in the list :py:obj:`cozy.project.RunResult.asserts_failed`
        """
        super().__init__(failure_state, state_id, "ASSERT_FAILED_STATE")
        self.cond = cond
        self.assertion = assertion

class PostconditionFailedState(TerminalState):
    """
    This class is used to indicate that execution failed due to an :py:class:`~cozy.directive.Assert` being satisfiable.

    :ivar Assert assertion: The assertion that was triggered.
    :ivar claripy.ast.bool cond: The condition that caused the assertion to trigger
    """
    def __init__(self, postcondition: Postcondition, cond: claripy.ast.bool, failure_state: SimState, state_id: int):
        """
        Constructor for AssertFailedState

        :param Postcondition assertion: The postcondition that was triggered.
        :param claripy.ast.bool: The condition which if falsified will trigger the postcondition assertion.
        :param SimState failure_state: The state that was created to test the postcondition assertion.
        :param int state_id: The identifier of the state, determined by its position in the list :py:obj:`cozy.project.RunResult.postconditions_failed`
        """
        super().__init__(failure_state, state_id, "POSTCONDITION_FAILED_STATE")
        self.cond = cond
        self.postcondition = postcondition

class ErrorState(TerminalState):
    """
    This class is used to indicate a state that resulted in an error (either my an execution error or :py:class:`~cozy.directive.ErrorDirective`).

    :ivar SimError error: The error that was thrown.
    :ivar traceback: The traceback attached to the error.
    """
    def __init__(self, error_record: ErrorRecord, state_id: int):
        """
        Constructor for ErrorState

        :param ErrorRecord error_record: The error thrown for this state.
        :param int state_id: The identifier of the state, determined by it's position in the list :py:obj:`cozy.project.RunResult.errored`
        """
        super().__init__(error_record.state, state_id, "ERROR_STATE")
        self.error: SimError = error_record.error
        self.traceback = error_record.traceback