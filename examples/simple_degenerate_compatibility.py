import os
import cozy.analysis as analysis
import cozy.claripy_ext as claripy_ext
from cozy.project import Project
from cozy.constants import *
import cozy.primitives as primitives
from cozy.directive import VirtualPrint
import cozy.execution_graph as execution_graph
import angr, claripy

def int_arg(name):
    return claripy.BVS(name, 32)

def bool_arg(name):
    return claripy.BVS(name, 32)

def run_temperature_symex(binary_path, args):
    proj = Project(binary_path)
    proj.add_prototype("check_avg_temp", "int f(int a, int b, int c)")
    sess = proj.session("check_avg_temp")
    return proj, sess.run(args)

def run_smoke_symex(binary_path, args):
    proj = Project(binary_path)
    proj.add_prototype("check_smoke_detectors", "int f(int a, int b, int c, int actual_fire)") # int instead of bool okay?
    sess = proj.session("check_smoke_detectors")
    return proj, sess.run(args)

def visualize_cmp(proj_1, proj_2, result_1, result_2):
    cmp_result = analysis.Comparison(result_1, result_2)
    execution_graph.visualize_comparison(proj_1, proj_2,
                                         result_1, result_2,
                                         cmp_result,
                                         num_examples=2,
                                         open_browser=True)

if __name__ == "__main__":

    root_path = os.path.join("test_programs", "degenerate_compatibility")

    temp_path = os.path.join(root_path, "temperature")
    temp_1    = os.path.join(temp_path, "temperature1")
    temp_2    = os.path.join(temp_path, "temperature2")

    temp_args = [int_arg(x) for x in ["a", "b", "c"]]
    
    temp_proj_1, temp_result_1 = run_temperature_symex(temp_1, temp_args)
    temp_proj_2, temp_result_2 = run_temperature_symex(temp_2, temp_args) 

    smoke_path = os.path.join(root_path, "smoke")
    smoke_1    = os.path.join(smoke_path, "smoke1")
    smoke_2    = os.path.join(smoke_path, "smoke2")
    smoke_3    = os.path.join(smoke_path, "smoke3")

    smoke_args = [int_arg(x) for x in ["x", "y", "z"]] + [bool_arg("actual_fire")]
    
    smoke_proj_1, smoke_result_1 = run_smoke_symex(smoke_1, smoke_args)
    smoke_proj_2, smoke_result_2 = run_smoke_symex(smoke_2, smoke_args)
    smoke_proj_3, smoke_result_3 = run_smoke_symex(smoke_3, smoke_args)


