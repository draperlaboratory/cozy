import angr

import cozy
import claripy

proj_a = cozy.project.Project('test_programs/int_ret_struct/ret_struct_a.o')
proj_b = cozy.project.Project('test_programs/int_ret_struct/ret_struct_b.o')

# Set up symbolic arguments
# Edit this section as needed for your application

vector_a = {
    "x": claripy.BVS("a_x", 32),
    "y": claripy.BVS("a_y", 32),
    "z": claripy.BVS("a_z", 32)
}

vector_b = {
    "x": claripy.BVS("b_x", 32),
    "y": claripy.BVS("b_y", 32),
    "z": claripy.BVS("b_z", 32)
}

program_args = [vector_a, vector_b]

cozy.types.register_type('struct Vector3 { int x; int y; int z; }', proj_a.arch)

def annotator(state, value, typ):
    # The value passed to this annotator will be a SimStructValue that was extracted by angr from the return of the function
    # Here we provide a simple annotation of the return value, splitting the SimStructValue into its component fields
    return {
        "x": value.x,
        "y": value.y,
        "z": value.z
    }

def run_a(proj: cozy.project.Project):
    proj.add_prototype('crossProduct', 'struct Vector3 crossProduct(struct Vector3 a, struct Vector3 b)')
    sess = proj.session('crossProduct')
    results = sess.run(program_args)
    results.annotate_return(annotator)
    return results

def run_b(proj: cozy.project.Project):
    proj.add_prototype('badCrossProduct', 'struct Vector3 badCrossProduct(struct Vector3 a, struct Vector3 b)')
    sess = proj.session('badCrossProduct')
    results = sess.run(program_args)
    results.annotate_return(annotator)
    return results

results_a = run_a(proj_a)
results_b = run_b(proj_b)

comparison_results = cozy.analysis.Comparison(results_a, results_b)

# Output reports pertaining to a single run
print(results_a.report(program_args))
print(results_b.report(program_args))

# Output results pertaining to the comparison
print("\nComparison Results:\n")
print(comparison_results.report(program_args))

cozy.execution_graph.visualize_comparison(proj_a, proj_b,
                                          results_a, results_b,
                                          comparison_results,
                                          args=program_args,
                                          num_examples=2, open_browser=True)