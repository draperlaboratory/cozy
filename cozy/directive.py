class Directive:
    pass

class Assert(Directive):
    def __init__(self, project, fun_name, offset, condition_fun, info_str=None):
        self.addr = project.find_symbol_addr(fun_name) + offset
        self.condition_fun = condition_fun
        self.info_str = info_str

class Assume(Directive):
    def __init__(self, project, fun_name, offset, condition_fun, info_str=None):
        self.addr = project.find_symbol_addr(fun_name) + offset
        self.condition_fun = condition_fun
        self.info_str = info_str

class VirtualPrint(Directive):
    # log_fun takes as input a state and returns a value to log. This value may be symbolic.
    # concrete_mapper takes as input a concretized version of the output from log_fun and returns a result
    # which is printed to the screen
    # For example, a log fun may return st.regs.eax to log the value of eax. But if eax represents a
    # 32 bit signed value, we want to pretty print to negative number. This is where concrete_mapper is useful.
    # In this example concrete_mapper would take a concrete bit vector representing a possible value of EAX
    # and return a Python integer (which can be negative). This is what is shown to the user.
    def __init__(self, project, fun_name, offset, log_fun, concrete_mapper=None, info_str="Unknown Virtual Print: "):
        self.addr = project.find_symbol_addr(fun_name) + offset
        self.log_fun = log_fun
        self.info_str = info_str
        self.concrete_mapper = concrete_mapper

class ErrorDirective(Directive):
    def __init__(self, project, fun_name, offset, info_str=None):
        self.addr = project.find_symbol_addr(fun_name) + offset
        if info_str is None:
            self.info_str = "Error at Instruction {}+{}".format(fun_name, hex(offset))
        else:
            self.info_str = info_str