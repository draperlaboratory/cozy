import os
import sys
import angr

class Stubber:

    def __init__(self, binary_path):
        proj = angr.Project(binary_path, load_options={"auto_load_libs":False})
        self.cfg = proj.analyses.CFGFast(show_progressbar=True)
        self.cg = self.cfg.functions.callgraph

    def extract_func(self, func_name):
        funcs = [f for f in [self.cfg.functions.function(node) for node in self.cg.nodes] if f.name == func_name]
        try:
            return funcs[0]
        except IndexError:
            raise ValueError("Function {} does not appear in call graph".format(func_name)) from None

    def callees(self, func_name):
        func = self.extract_func(func_name)
        return [self.cfg.functions[addr] for addr in self.cg.successors(func.addr)]


if __name__ == "__main__":
    binary_path = "../test_programs/GridIDPS/build/amp_challenge_arm.ino_unstripped.elf"
    func_name = "loop"
    stubber = Stubber(binary_path)
    loop_callees = stubber.callees(func_name)
    print(loop_callees)
