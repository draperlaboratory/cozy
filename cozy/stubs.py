import os
import sys
import angr

class Stubber:
    """A Stubber outputs Python source code that represents stubs for the callees of a given binary function.

       If `foo` is the function to be analyzed, and `foo` calls a two-argument function `bar`, then the following stub
       will be among those generated for `foo`:

       .. code-block:: python

       class bar(angr.SimProcedure):
           def run(self, arg0, arg1):
               pass

       The stub can then be filled out and used during symbolic execution.

       :param str binary_path: Path for the binary under analysis.
       :ivar angr.analyses.cfg.cfg_fast.CFGFast cfg: CFG for the binary.
       :ivar networkx.classes.multidigraph.MultiDiGraph cg: Call graph for the binary.
    """

    def __init__(self, binary_path: str):
        proj = angr.Project(binary_path, load_options={"auto_load_libs":False})
        self.cfg = proj.analyses.CFGFast(show_progressbar=True)
        proj.analyses.CompleteCallingConventions(recover_variables=True) 
        self.cg = self.cfg.functions.callgraph

    def extract_func(self, func_name: str) -> angr.knowledge_plugins.functions.function.Function:
        """Returns the function with the given name from the CFG.

        :param str func_name: Name of the function to extract.
        :return: Function with the given name.
        :rtype: angr.knowledge_plugins.functions.function.Function
        """
        funcs = [f for f in [self.cfg.functions.function(node) for node in self.cg.nodes] if f.name == func_name]
        try:
            return funcs[0]
        except IndexError:
            raise ValueError("Function {} does not appear in call graph".format(func_name)) from None

    def get_callees(self, func_name: str) -> list[angr.knowledge_plugins.functions.function.Function]:
        """Returns the list of functions called by function `func_name`.

        :param str func_name: Name of the caller function.
        :return: The list of functions called by `func_name`.
        :rtype: list[angr.knowledge_plugins.functions.function.Function] 
        """
        func = self.extract_func(func_name)
        return [self.cfg.functions[addr] for addr in self.cg.successors(func.addr)]

    def make_stub(self, func: angr.knowledge_plugins.functions.function.Function) -> str:
        """Returns an empty Python class definition (in string form) named after `func` that inherits from `angr.SimProcedure`.

        :param angr.knowledge_plugins.functions.function.Function func: Function to be stubbed.
        :return: Empty Python class definition representing a symbolic execution stub for function `func`.
        :rtype: str
        """
        argstring = ", ".join(["self"] + ["arg" + str(i) for i in range(len(func.prototype.args))])
        template = """
class {}(angr.SimProcedure):
    def run({}):
        pass"""
        return template.format(func.name, argstring)

    def make_callee_stubs(self, func_name: str) -> list[str]:
        """Returns a list of stubs for the callees of function `func_name`.

        :param str func_name: Name of the caller function.
        :return: Stubs for the callees of function `func_name`.
        :rtype: list[str]
        """
        callees = self.get_callees(func_name)
        return [self.make_stub(callee) for callee in callees]

if __name__ == "__main__":
    # Example usage
    unstripped_binary_path = "../test_programs/GridIDPS/build/amp_challenge_arm.ino_unstripped.elf"
    func_name = "loop"
    stubber = Stubber(unstripped_binary_path)
    loop_callees = stubber.get_callees(func_name)
    for lc in loop_callees:
        print(stubber.make_stub(lc))

