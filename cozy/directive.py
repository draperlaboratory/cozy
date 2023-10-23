from collections.abc import Callable

import claripy
from angr import SimState

class Directive:
    """
    Abstract base class for all directives.
    """
    pass

class Assert(Directive):
    """
    An assert directive sets a breakpoint at a certain address. An assert is triggered if there is a concrete input which would cause the assertion condition to be satisfied.

    :ivar int addr: The program address this assert is attached to.
    :ivar Callable[[SimState], claripy.ast.bool] condition_fun: When the program reaches the desired address, the SimState will be passed to this function, and an assertion condition should be returned. This is then used internally by the SAT solver, along with the state's accumulated constraints.
    :ivar str | None info_str: Human readable label for this assertion, printed to the user if the assert is triggered.
    """
    def __init__(self, addr: int, condition_fun: Callable[[SimState], claripy.ast.bool], info_str: str | None=None):
        """
        Constructor for an Assert object.

        :param int addr: The address at which the assert will be triggered.
        :param Callable[[SimState], claripy.ast.bool] condition_fun: When the program reaches the desired address, the SimState will be passed to this function, and an assertion condition should be returned. This is then used internally by the SAT solver, along with the state's accumulated constraints.
        :param str | None info_str: Human readable label for this assertion, printed to the user if the assert is triggered.
        """
        self.addr = addr
        self.condition_fun = condition_fun
        self.info_str = info_str

    @staticmethod
    def from_fun_offset(project, fun_name: str, offset: int, condition_fun: Callable[[SimState], claripy.ast.bool], info_str: str | None=None):
        """
        Factory for an Assert object set at a certain offset from a function start.

        :param cozy.project.Project project: The project which this assert is attached to. The project is used to compute the address of the assert.
        :param fun_name str: The name of the function in which this assert will be located.
        :param offset int: The offset into the function in which this assert will be located.
        :param Callable[[SimState], claripy.ast.bool] condition_fun: When the program reaches the desired address, the SimState will be passed to this function, and an assertion condition should be returned. This is then used internally by the SAT solver, along with the state's accumulated constraints.
        :param str | None info_str: Human readable label for this assertion, printed to the user if the assert is triggered.
        :return: A new Assert object at the desired function offset.
        :rtype: Assert
        """
        return Assert(project.find_symbol_addr(fun_name) + offset, condition_fun, info_str=info_str)

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
    :ivar Callable[[SimState], claripy.ast.Base] log_fun: This function takes in the current state and returns a claripy AST which should be logged. This value may be symbolic.
    :ivar str info_str: Human readable label for this virtual print.
    :ivar Callable[[claripy.ast.Base], any] | None concrete_mapper: concrete_mapper takes as input a concretized version of the output from log_fun and returns a result which is printed to the screen. For example, a log fun may return state.regs.eax to log the value of eax. But if eax represents a 32 bit signed value, we want to pretty print to negative number. This is where concrete_mapper is useful. In this example concrete_mapper would take a concrete bit vector representing a possible value of EAX and return a Python integer (which can be negative). This is what is shown to the user.
    """
    def __init__(self, addr: int, log_fun: Callable[[SimState], claripy.ast.Base], concrete_mapper: Callable[[claripy.ast.Base], any] | None=None, info_str: str="Unknown Virtual Print: "):
        """
        Constructor for a VirtualPrint object.

        :param int addr: The program address this virutal print is attached to.
        :param Callable[[SimState], claripy.ast.Base] log_fun: This function takes in the current state and returns a claripy AST which should be logged. This value may be symbolic.
        :param Callable[[claripy.ast.Base], any] | None concrete_mapper: concrete_mapper takes as input a concretized version of the output from log_fun and returns a result which is printed to the screen. For example, a log fun may return state.regs.eax to log the value of eax. But if eax represents a 32 bit signed value, we want to pretty print to negative number. This is where concrete_mapper is useful. In this example concrete_mapper would take a concrete bit vector representing a possible value of EAX and return a Python integer (which can be negative). This is what is shown to the user.
        :param str info_str: Human readable label for this virtual print.
        """
        self.addr = addr
        self.log_fun = log_fun
        self.info_str = info_str
        self.concrete_mapper = concrete_mapper

    @staticmethod
    def from_fun_offset(project, fun_name: str, offset: int, log_fun: Callable[[SimState], claripy.ast.Base], concrete_mapper: Callable[[claripy.ast.Base], any] | None=None, info_str: str | None = None):
        """
        Factory for VirtualPrint object set at a certain offset from a function start.

        :param cozy.project.Project project: The project which this virtual print is attached to. The project is used to compute the address of the virtual print.
        :param str fun_name: The name of the function in which this virtual print will be located.
        :param int offset: The offset into the function in which this virtual print will be located.
        :param Callable[[claripy.ast.Base], any] | None concrete_mapper: concrete_mapper takes as input a concretized version of the output from log_fun and returns a result which is printed to the screen. For example, a log fun may return state.regs.eax to log the value of eax. But if eax represents a 32 bit signed value, we want to pretty print to negative number. This is where concrete_mapper is useful. In this example concrete_mapper would take a concrete bit vector representing a possible value of EAX and return a Python integer (which can be negative). This is what is shown to the user.
        :param str info_str: Human readable label for this virtual print.
        :return: A new VirtualPrint object at the desired function offset.
        :rtype: VirtualPrint
        """
        return VirtualPrint(project.find_symbol_addr(fun_name) + offset, log_fun, concrete_mapper=concrete_mapper, info_str=info_str)

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
