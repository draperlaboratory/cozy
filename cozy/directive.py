from collections.abc import Callable
from enum import Enum

import claripy
from angr import SimState

class Directive:
    """
    Abstract base class for all directives.
    """
    pass

class AssertType(Enum):
    """
    An enum to determine the type of assertion.
    """

    ASSERT_MUST = 0
    """
    This type of assert will be triggered if the assertion condition can be falsified. This assertion type replicates
    the behaviour of assertions as used in a typical testing environment. More precisely, this assertion uses
    universal quantification. The assertion fails if the following condition does not hold: forall x . P(x), where
    x is the program input, and P is the assertion condition.
    """

    ASSERT_CAN = 1
    """
    This type of assert will be triggered if the assertion condition cannot be satisfied, under the constraints of
    the local state. This assertion type is a dual to ASSERT_MUST, and an exact analogue does not exist from
    typical testing environments. More precisely, this assertion uses existential quantification. The assertion
    fails if the following condition does not hold: exists x . P(x), where x is the program input, P is the
    assertion condition, and C is the state's constraints.
    """

    ASSERT_CAN_GLOBAL = 2
    """
    This is type of assert is like ASSERT_CAN, but is computed under a global setting. If on any path the local
    assertion exists x . P(x) holds, then all cases where the assertion failed will be scrubbed from the output.
    This is much the same E from computation tree logic, which is also a global property. Note that this assertion
    type should only be used in cases where the exploration is complete - ie all states can be explored. 
    """

class Assert(Directive):
    """
    An assert directive sets a breakpoint at a certain address.

    :ivar int addr: The program address this assert is attached to.
    :ivar Callable[[SimState], claripy.ast.bool] condition_fun: When the program reaches the desired address, the\
    SimState will be passed to this function, and an assertion condition should be returned. This is then used\
    internally by the SAT solver, along with the state's accumulated constraints.
    :ivar str | None info_str: Human readable label for this assertion, printed to the user if the assert is triggered.
    :ivar AssertType assert_type: The type of assert.
    """
    def __init__(self, addr: int, condition_fun: Callable[[SimState], claripy.ast.bool], info_str: str | None=None,
                 assert_type: AssertType=AssertType.ASSERT_MUST):
        """
        Constructor for an Assert object.

        :param int addr: The address at which the assert will be triggered.
        :param Callable[[SimState], claripy.ast.bool] condition_fun: When the program reaches the desired address, the\
        SimState will be passed to this function, and an assertion condition should be returned. This is then used\
        internally by the SAT solver, along with the state's accumulated constraints.
        :param str | None info_str: Human readable label for this assertion, printed to the user if the assert is\
        triggered.
        :param AssertType assert_type: The type of assert to construct.
        """
        self.addr = addr
        self.condition_fun = condition_fun
        self.info_str = info_str
        self.assert_type = assert_type

    @staticmethod
    def from_fun_offset(project, fun_name: str, offset: int, condition_fun: Callable[[SimState], claripy.ast.bool],
                        info_str: str | None=None, assert_type: AssertType=AssertType.ASSERT_MUST):
        """
        Factory for an Assert object set at a certain offset from a function start.

        :param cozy.project.Project project: The project which this assert is attached to. The project is used to compute the address of the assert.
        :param fun_name str: The name of the function in which this assert will be located.
        :param offset int: The offset into the function in which this assert will be located.
        :param Callable[[SimState], claripy.ast.bool] condition_fun: When the program reaches the desired address, the\
        SimState will be passed to this function, and an assertion condition should be returned. This is then used\
        internally by the SAT solver, along with the state's accumulated constraints.
        :param str | None info_str: Human readable label for this assertion, printed to the user if the assert is triggered.
        :param AssertType assert_type: The type of assert to construct.
        :rtype: Assert
        """
        return Assert(project.find_symbol_addr(fun_name) + offset, condition_fun, info_str=info_str, assert_type=assert_type)

class Assume(Directive):
    """
    An assume directive sets a breakpoint at a certain address. An assume simply adds an extra constraint to the state's accumulated constraints before resuming execution. An assume is useful for adding a precondition.

    :ivar int addr: The program address this assume is attached to.
    :ivar Callable[[SimState], claripy.ast.bool] condition_fun: When the program reaches the desired address, the SimState will be passed to this function, and a condition should be returned. This condition is then attached to the state's set of constraints.
    :ivar str | None info_str: Human readable label for this assume.
    """
    def __init__(self, addr: int, condition_fun: Callable[[SimState], claripy.ast.bool], info_str: str | None=None):
        """
        Constructor for an Assume object.

        :param int addr: The address at which the assume will be triggered.
        :param Callable[[SimState], claripy.ast.bool] condition_fun: When the program reaches the desired address, the SimState will be passed to this function, and an assumption should be returned. This assumption is attached to the state's constraints for future execution.
        :param str | None info_str: Human readable label for this assume.
        """
        self.addr = addr
        self.condition_fun = condition_fun
        self.info_str = info_str

    @staticmethod
    def from_fun_offset(project, fun_name: str, offset: int, condition_fun: Callable[[SimState], claripy.ast.bool], info_str: str | None=None):
        """
        Factory for an Assume object set at a certain offset from a function start.

        :param cozy.project.Project project: The project this assume is attached to.
        :param fun_name str: The name of the function in which this assume will be located.
        :param offset int: The offset into the function in which this assume will be located.
        :param Callable[[SimState], claripy.ast.bool] condition_fun: When the program reaches the desired address, the SimState will be passed to this function, and an assumption should be returned. This assumption is attached to the state's constraints for future execution.
        :param str | None info_str: Human readable label for this assume.
        :return: A new Assume object at the desired function offset.
        :rtype: Assume
        """
        return Assume(project.find_symbol_addr(fun_name) + offset, condition_fun, info_str=info_str)

class VirtualPrint(Directive):
    """
    This directive is used to log some piece of information about the program in a list attached to the state. When execution reaches the desired address, the log function will be called, and the result will be saved inside the state's globals dictionary.

    :ivar int addr: The program address this virutal print is attached to.
    :ivar Callable[[SimState], claripy.ast.Base] log_fun: This function takes in the current state and returns a\
    claripy AST which should be logged. This value may be symbolic.
    :ivar str info_str: Human readable label for this virtual print.
    :ivar str label: Internal label used for side effect alignment. Side effects (including virtual prints) are diffed\
    if they have the same label.
    :ivar Callable[[claripy.ast.Base], any] | None concrete_post_processor: concrete_post_processor takes as input a\
    concretized version of the output from log_fun and returns a result which is printed to the screen. For example, a\
    log fun may return state.regs.eax to log the value of eax. But if eax represents a 32 bit signed value, we want to\
    pretty print to negative number. This is where concrete_post_processor is useful. In this example\
    concrete_post_processor would take a concrete bit vector representing a possible value of EAX and return a Python\
    integer (which can be negative). This is what is shown to the user.
    """
    def __init__(self, addr: int, log_fun: Callable[[SimState], claripy.ast.Base], concrete_post_processor: Callable[[claripy.ast.Base], any] | None=None, info_str: str="Unknown Virtual Print: ", label=None):
        """
        Constructor for a VirtualPrint object.

        :param int addr: The program address this virutal print is attached to.
        :param Callable[[SimState], claripy.ast.Base] log_fun: This function takes in the current state and returns a\
        claripy AST which should be logged. This value may be symbolic.
        :param Callable[[claripy.ast.Base], any] | None concrete_post_processor: concrete_post_processor takes as input\
        a concretized version of the output from log_fun and returns a result which is printed to the screen. For\
        example, a log fun may return state.regs.eax to log the value of eax. But if eax represents a 32 bit signed\
        value, we want to pretty print to negative number. This is where concrete_post_processor is useful. In this\
        example concrete_post_processor would take a concrete bit vector representing a possible value of EAX and\
        return a Python integer (which can be negative). This is what is shown to the user.
        :param str info_str: Human readable label for this virtual print.
        :param str label: Internal label used for side effect alignment. Side effects (including virtual prints) are\
        diffed if they have the same label.
        """
        self.addr = addr
        self.log_fun = log_fun
        self.info_str = info_str
        self.concrete_post_processor = concrete_post_processor
        self.label = label

    def effect_concrete_post_processor(self, concrete_value):
        if self.concrete_post_processor is not None:
            concrete_value = self.concrete_post_processor(concrete_value)
        return "{}: {}".format(self.info_str, concrete_value)

    @staticmethod
    def from_fun_offset(project, fun_name: str, offset: int, log_fun: Callable[[SimState], claripy.ast.Base], concrete_post_processor: Callable[[claripy.ast.Base], any] | None=None, info_str: str | None = None, label=None):
        """
        Factory for VirtualPrint object set at a certain offset from a function start.

        :param cozy.project.Project project: The project which this virtual print is attached to. The project is used to compute the address of the virtual print.
        :param str fun_name: The name of the function in which this virtual print will be located.
        :param int offset: The offset into the function in which this virtual print will be located.
        :param Callable[[SimState], claripy.ast.Base] log_fun: This function takes in the current state and returns a\
        claripy AST which should be logged. The return value may be symbolic.
        :param Callable[[claripy.ast.Base], any] | None concrete_post_processor: concrete_post_processor takes as input\
        a concretized version of the output from log_fun and returns a result which is printed to the screen. For\
        example, a log fun may return state.regs.eax to log the value of eax. But if eax represents a 32 bit signed\
        value, we want to pretty print to negative number. This is where concrete_post_processor is useful. In this\
        example concrete_post_processor would take a concrete bit vector representing a possible value of EAX and\
        return a Python integer (which can be negative). This is what is shown to the user.
        :param str info_str: Human readable label for this virtual print.
        :param str label: Internal label used for side effect alignment. Side effects (including virtual prints) are\
        diffed if they have the same label.
        :return: A new VirtualPrint object at the desired function offset.
        :rtype: VirtualPrint
        """
        return VirtualPrint(project.find_symbol_addr(fun_name) + offset, log_fun, concrete_post_processor=concrete_post_processor, info_str=info_str, label=label)

class ErrorDirective(Directive):
    """
    If the program execution reaches the desired address, the state will be considered to be in an errored state and will be moved to the errored cache. This state will have no further execution.

    :ivar int addr: The program address this error directive is attached to.
    :ivar str: Human readable information for this error directive.
    """
    def __init__(self, addr: int, info_str: str | None=None):
        """
        Constructor for an ErrorDirective object.

        :param int addr: The program address this error directive is attached to.
        :param str info_str: Human readable information for this error directive.
        """
        self.addr = addr
        self.info_str = info_str

    @staticmethod
    def from_fun_offset(project, fun_name: str, offset: int, info_str: str | None=None):
        """
        Factory for ErrorDirective object set at a certain offset from a function start.

        :param cozy.project.Project project: The project this error directive should be attached to.
        :param str fun_name: The name of the function in which this error directive will be located.
        :param int offset: The offset into the function in which this error directive will be located.
        :param str | None info_str: Human readable information for this error directive.
        :return: A new ErrorDirective object at the desired function offset.
        :rtype: ErrorDirective
        """
        if info_str is None:
            info_str = "Error at Instruction {}+{}".format(fun_name, hex(offset))
        return ErrorDirective(project.find_symbol_addr(fun_name) + offset, info_str=info_str)

class Breakpoint(Directive):
    """
    This directive is used to halt execution at some particular address, and pass the current state to the provided
    breakpoint function, which can then either modify the state or do some other side effect (like executing a Python
    print() call).

    :ivar int addr: The program address this breakpoint is attached to.
    :ivar Callable[[SimState], None] breakpoint_fun: This function takes in the state reached by the program at the\
    attachment point.
    """
    def __init__(self, addr: int, breakpoint_fun: Callable[[SimState], None]):
        """
        Constructor for a VirtualPrint object.

        :param int addr: The program address this breakpoint is attached to.
        :param Callable[[SimState], None] breakpoint_fun: This function takes in the state reached by the program at\
        the attachment point.
        """
        self.addr = addr
        self.breakpoint_fun = breakpoint_fun

    @staticmethod
    def from_fun_offset(project, fun_name: str, offset: int, breakpoint_fun: Callable[[SimState], None]):
        """
        Factory for VirtualPrint object set at a certain offset from a function start.

        :param cozy.project.Project project: The project which this virtual print is attached to. The project is used to compute the address of the virtual print.
        :param str fun_name: The name of the function in which this virtual print will be located.
        :param int offset: The offset into the function in which this virtual print will be located.
        :param Callable[[SimState], None] breakpoint_fun: This function takes in the state reached by the program at\
        the attachment point.
        :return: A new Breakpoint object at the desired function offset.
        :rtype: Breakpoint
        """
        return Breakpoint(project.find_symbol_addr(fun_name) + offset, breakpoint_fun)

class Postcondition(Directive):
    """
    A Postcondition is a special type of assertion that is executed on terminal states for which execution has been
    completed. This is identical to attaching an ASSERT_MUST assertion to all return points. This type of property
    is useful for verifying that a property holds in all terminal states. Note that if you are looking to add a
    precondition, you can add your proposition to the session before the run via
    :py:meth:`cozy.Session.add_constraints`.
    """

    def __init__(self, condition_fun: Callable[[SimState], claripy.ast.bool], info_str: str | None=None,
                 assert_type=AssertType.ASSERT_MUST):
        """
        :param Callable[[SimState], claripy.ast.bool] condition_fun: When the program reaches a terminal state, the\
        SimState will be passed to this function, and an assertion condition should be returned. This is then used\
        internally by the SAT solver, along with the state's accumulated constraints.
        :param str | None info_str: Human readable label for this postcondition assertion, printed to the user if the\
        assert is triggered.
        :param AssertType assert_type: The type of assert to construct.
        """
        self.condition_fun = condition_fun
        self.info_str = info_str
        self.assert_type = assert_type