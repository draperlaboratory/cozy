import cozy
import claripy

proj_prepatched = cozy.project.Project('test_programs/cross_language_sort/c/insertion_sort')
proj_postpatched = cozy.project.Project('test_programs/cross_language_sort/rust/target/release-with-debug/bubble_sort_rust')

# Set up symbolic arguments
# Edit this section as needed for your application

max_num_count = 3
array_numbers = []

for i in range(max_num_count):
    array_numbers.append(claripy.BVS(f'num_{i}', 32))

length = claripy.BVS('length', 64)

def run_c(proj: cozy.project.Project):
    len_32 = length[31:0]

    proj.add_prototype('insertion_sort', 'void insertion_sort(int n, int *p)')
    sess = proj.session('insertion_sort')
    sess.add_constraints(len_32.SGE(0), len_32.SLE(max_num_count))

    arr = sess.malloc(4 * max_num_count)
    for i in range(max_num_count):
        sess.mem[arr + i * 4].int = array_numbers[i]
        sess.annotate_memory(("input_arr", i), sess.mem[arr + i * 4].int)

    return sess.run([len_32, arr])

def run_rust(proj: cozy.project.Project):
    #fun_name = "_ZN7is_rust14insertion_sort17he7ff3aca5b6b243aE"
    fun_name = "_ZN16bubble_sort_rust11bubble_sort17hc64838fb066d9ff6E"
    cozy.types.register_type('struct i32_arr { int *p; unsigned long long size; }', proj.arch)
    proj.add_prototype(fun_name, 'void bubble_sort(struct i32_arr)')

    sess = proj.session(fun_name)
    sess.add_constraints(length.UGE(0), length.ULE(max_num_count))

    arr = sess.malloc(4 * max_num_count)
    for i in range(max_num_count):
        sess.mem[arr + i * 4].int = array_numbers[i]
        sess.annotate_memory(("input_arr", i), sess.mem[arr + i * 4].int)

    return sess.run([{"p": arr, "size": length}])

pre_results = run_c(proj_prepatched)
post_results = run_rust(proj_postpatched)

comparison_results = cozy.analysis.Comparison(pre_results, post_results, comparisons=cozy.analysis.ComparisonOptions.COMPARE_ANNOTATED_MEMORY)
program_args = {"length": length, "array_numbers": array_numbers}

def concrete_post_processor(args):
    # This function will post process a concretized version of
    # program_args. In this case we will loop over the 8 bit
    # binary bit vectors and convert them to Python characters.
    ret = dict(args)
    ret["array_numbers"] = [cozy.primitives.from_twos_comp(n.concrete_value, 32) for n in ret["array_numbers"]]
    return ret

# Output reports pertaining to a single run
print(pre_results.report(program_args, concrete_post_processor=concrete_post_processor))
print(post_results.report(program_args, concrete_post_processor=concrete_post_processor))

# Output results pertaining to the comparison
print("\nComparison Results:\n")
print(comparison_results.report(program_args, concrete_post_processor=concrete_post_processor))

cozy.execution_graph.visualize_comparison(proj_prepatched, proj_postpatched,
                                          pre_results, post_results,
                                          comparison_results,
                                          args=program_args,
                                          num_examples=2, open_browser=True, concrete_post_processor=concrete_post_processor)