import os

def yesno_question(prompt):
    result = input(prompt + " (y/n): ")
    if result == "y" or result == "yes":
        return True
    elif result == "n" or result == "no":
        return False
    else:
        print("Invalid selection")
        return yesno_question(prompt)

def input_default(prompt, default_value):
    result = input('{} (or leave empty to use default value: "{}")\n'.format(prompt, default_value))
    if result == "":
        return default_value
    else:
        return result

def generate():
    print("Welcome to the cozy Python script generation wizard!")
    filename = None
    while filename is None:
        filename = input("Please enter the filename for your new cozy Python script:\n")
        if os.path.isfile(filename):
            if not yesno_question("This file already exists! Would you like to overwrite this file?"):
                filename = None
    prepatch_filename = input_default("Please enter the filename for the prepatched binary.", "prepatch.elf")
    postpatch_filename = input_default("Please enter the filename for the postpatched binary.", "postpatch.elf")
    fun_name = input_default("Please enter the name or address of the function you want to execute.", "main")
    if fun_name.startswith("0x"):
        fun_name_processed = int(fun_name, 16)
    elif fun_name.isdigit():
        fun_name_processed = int(fun_name)
    else:
        fun_name_processed = fun_name
    if isinstance(fun_name_processed, int):
        fun_signature_prompt = "Please enter the function signature of the function at {}.".format(fun_name)
    else:
        fun_signature_prompt = "Please enter the function signature of the {} function.".format(fun_name)
    fun_signature = input_default(fun_signature_prompt, "int main(int argc, char* argv[])")
    output_hooks = yesno_question("Will you be using hooks to simulate hard to execute functions?")
    textual_report = yesno_question("Would you like to output a textual version of the diff upon completion?")
    visualize_report = yesno_question("Would you like to visualize the diff upon completion?")
    use_concolic = yesno_question("Would you like to use concolic execution instead of typical symbolic execution while exploring?")
    if use_concolic:
        use_concolic_complete = yesno_question("Would you like to explore all possible states when performing concolic execution?")
    else:
        use_concolic_complete = False
    dump_results = yesno_question("Would you like to dump the results to a JSON file suitable for visualization in the future? Note that you can also save the results via the Files menu in the visualization interface.")
    if dump_results:
        prepatch_results_filename = input_default("Enter the prepatch results filename.", "prepatch.json")
        postpatch_results_filename = input_default("Enter the postpatch results filename.", "postpatch.json")
    else:
        prepatch_results_filename = ''
        postpatch_results_filename = ''

    code = '''import cozy
import claripy
import angr'''

    if use_concolic:
        code += '''from cozy.concolic.heuristics import CyclomaticComplexityTermination, BBTransitionCandidate
from cozy.concolic.session import JointConcolicSession'''

    code += '''

proj_prepatched = cozy.project.Project('{}')
proj_postpatched = cozy.project.Project('{}')

# Set up symbolic arguments
# Edit this section as needed for your application

# A symbol 32 bit symbolic argument
my_arg_sym = claripy.BVS('my_arg', 32)

# A more complex example of setting up a string of characters
MAX_STR_SIZE = 10
# Set up symbols to use in string that will be passed to our function
str_sym = [claripy.BVS('char_{{}}'.format(i), 8) for i in range(MAX_STR_SIZE - 1)]
'''.format(prepatch_filename, postpatch_filename)

    if use_concolic:
        code += '''
# The following set is only used for concolic execution.
# The concolic execution joint simulator needs to know about all symbolic values in the simulation
sym_args = set()
sym_args.add(my_arg_sym)
sym_args.update(str_sym)'''

    code += '''
# Let's assume that our string must be terminated with a 0
str_sym.append(claripy.BVV(0, 8))

'''

    if output_hooks:
        code += '''class my_hook(angr.SimProcedure):
    def run(self, arg):
        return 0

'''

    code += '''def {}(proj: cozy.project.Project):
'''.format('setup' if use_concolic else 'run')

    if output_hooks:
        code += '''    proj.hook_symbol('my_hook_fun_name', my_hook)
    
'''

    if isinstance(fun_name_processed, int):
        code += '''    proj.add_prototype({}, '{}')
    sess = proj.session({})
'''.format(fun_name, fun_signature, fun_name)
    else:
        code += '''    proj.add_prototype('{}', '{}')
    sess = proj.session('{}')
'''.format(fun_name, fun_signature, fun_name)

    code += '''    
    # Add preconditions to the session
    sess.add_constraints(my_arg_sym.SGE(0)) # Constrain my_arg_sym >= 0
'''

    code += '''    
    # Set up the session's memory before execution
    
    # Allocate some memory to use for our string
    str_addr = sess.malloc(MAX_STR_SIZE)
    for i in range(MAX_STR_SIZE):
        sess.mem[str_addr + i].char = str_sym[i]
    '''

    code += '''    
    # The following is an example assertion
    def index_assertion(state):
        index = state.regs.r2
        # Assert that in this state, the index is in range
        # This is an example of a buffer overflow assertion
        return (index.SGE(0) & index.SLT(MAX_STR_SIZE))
    '''
    if isinstance(fun_name_processed, int):
        code += '''sess.add_directives(cozy.directive.Assert.from_fun_offset(proj, {}, 0x20, index_assertion, "index out of bounds"))
    '''.format(fun_name)
    else:
        code += '''sess.add_directives(cozy.directive.Assert.from_fun_offset(proj, '{}', 0x20, index_assertion, "index out of bounds"))
    '''.format(fun_name)

    if use_concolic:
        code += '''
    return (sess, [my_arg_sym, str_addr])

'''
    else:
        code += '''
    return sess.run([my_arg_sym, str_addr])

'''

    if use_concolic:
        code += '''(pre_sess, pre_args) = setup(proj_prepatched)
(post_sess, post_args) = setup(proj_postpatched)

'''
        if use_concolic_complete:
            code += '''joint_sess = JointConcolicSession(pre_sess, post_sess)
'''
        else:
            code += '''joint_sess = JointConcolicSession(
    pre_sess, post_sess,
    candidate_heuristic_left=BBTransitionCandidate(),
    candidate_heuristic_right=BBTransitionCandidate(),
    termination_heuristic_left=CyclomaticComplexityTermination.from_session(pre_sess),
    termination_heuristic_right=CyclomaticComplexityTermination.from_session(post_sess)
)
'''
        code += '''(pre_results, post_results) = joint_sess.run(pre_args, post_args, sym_args)

'''
    else:
        code += '''pre_results = run(proj_prepatched)
post_results = run(proj_postpatched)

'''

    code += '''comparison_results = cozy.analysis.Comparison(pre_results, post_results)
program_args = {"my_arg": my_arg_sym, "str": str_sym}
'''

    code += '''
def concrete_post_processor(args):
    # This function will post process a concretized version of
    # program_args. In this case we will loop over the 8 bit
    # binary bit vectors and convert them to Python characters.
    ret = dict(args)
    ret["str"] = [chr(r.concrete_value) for r in args["str"]]
    return ret

'''

    if textual_report:
        code += '''# Output reports pertaining to a single run
print(pre_results.report(program_args, concrete_post_processor=concrete_post_processor))
print(post_results.report(program_args, concrete_post_processor=concrete_post_processor))

# Output results pertaining to the comparison
print("\\nComparison Results:\\n")
print(comparison_results.report(program_args, concrete_post_processor=concrete_post_processor))

'''

    if dump_results:
        code += '''cozy.execution_graph.dump_comparison(
    proj_prepatched, proj_postpatched,
    pre_results, post_results, comparison_results,
    "{}", "{}",
    args=program_args, num_examples=2
)

'''.format(prepatch_results_filename, postpatch_results_filename)

    if visualize_report:
        code += '''cozy.execution_graph.visualize_comparison(
    proj_prepatched, proj_postpatched,
    pre_results, post_results,
    comparison_results,
    concrete_post_processor=concrete_post_processor, args=program_args,
    num_examples=2, open_browser=True)'''

    with open(filename, 'w') as f:
        f.write(code)

    print("Templated code written to {}!".format(filename))

if __name__ == "__main__":
    generate()