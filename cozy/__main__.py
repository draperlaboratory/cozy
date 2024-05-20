import os
import asyncio
from enum import Enum
from textual.app import App, ComposeResult
from textual.widgets import OptionList, Markdown, Input, DirectoryTree, Header
from textual.widgets.option_list import Option
from textual.containers import VerticalScroll, Horizontal, Vertical
from textual.message import Message

class Results():
    def to_string(self):

        code = '''import cozy
import claripy
import angr'''

        if self.concolic:
            code += '''
from cozy.concolic.heuristics import CyclomaticComplexityTermination, BBTransitionCandidate
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
'''.format(self.prepatched_path, self.postpatched_path)

        if self.concolic:
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

        if self.hooks:
            code += '''class my_hook(angr.SimProcedure):
    def run(self, arg):
        return 0

'''

        code += '''def {}(proj: cozy.project.Project):
'''.format('setup' if self.concolic else 'run')

        if self.hooks:
            code += '''    proj.hook_symbol('my_hook_fun_name', my_hook)
    
'''

        if isinstance(self.fun_name_processed, int):
            code += '''    proj.add_prototype({}, '{}')
    sess = proj.session({})
'''.format(self.fun_name, self.fun_signature, self.fun_name)
        else:
            code += '''    proj.add_prototype('{}', '{}')
    sess = proj.session('{}')
'''.format(self.fun_name, self.fun_signature, self.fun_name)

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
                   
    # The following is an example assertion
    def index_assertion(state):
        index = state.regs.r2
        # Assert that in this state, the index is in range
        # This is an example of a buffer overflow assertion
        return (index.SGE(0) & index.SLT(MAX_STR_SIZE))
    '''
        if isinstance(self.fun_name_processed, int):
            code += '''sess.add_directives(cozy.directive.Assert.from_fun_offset(proj, {}, 0x20, index_assertion, "index out of bounds"))
        '''.format(self.fun_name)
        else:
            code += '''sess.add_directives(cozy.directive.Assert.from_fun_offset(proj, '{}', 0x20, index_assertion, "index out of bounds"))
    '''.format(self.fun_name)

        if self.concolic:
            code += '''
    return (sess, [my_arg_sym, str_addr])

'''
        else:
            code += '''
    return sess.run([my_arg_sym, str_addr])

'''

        if self.concolic:
            code += '''(pre_sess, pre_args) = setup(proj_prepatched)
(post_sess, post_args) = setup(proj_postpatched)

'''
            if self.concolic_complete:
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

        if self.textual_report:
            code += '''# Output reports pertaining to a single run
print(pre_results.report(program_args, concrete_post_processor=concrete_post_processor))
print(post_results.report(program_args, concrete_post_processor=concrete_post_processor))

# Output results pertaining to the comparison
print("\\nComparison Results:\\n")
print(comparison_results.report(program_args, concrete_post_processor=concrete_post_processor))

'''

        if self.dump:
            code += '''cozy.execution_graph.dump_comparison(
    proj_prepatched, proj_postpatched,
    pre_results, post_results, comparison_results,
    "{}",
    args=program_args, num_examples=2
)

'''.format(self.dump_name)
        return code

class Stage(Enum):
    confirm_start = 1
    request_script_name = 2
    confirm_script_clobber = 3
    request_prepatched = 4
    request_postpatched = 5
    request_function_name = 6
    request_signature = 7
    request_concolic = 8
    request_concolic_complete = 9
    request_hooks = 10
    request_textual_report = 11
    request_visualization = 12
    request_dump = 13
    request_dump_name = 14
    complete = 15

class Wizard(App):

    def __init__(self):
        self.results = Results()
        super().__init__()

    CSS = """
    Screen {
        padding:1
    }
    """

    def compose(self) -> ComposeResult:
        self.stage = Stage.confirm_start
        yield Horizontal(
            body := VerticalScroll(
                Markdown("### Cozy Wizard"),
                Markdown("🧙 Would you like to create a new cozy script?", id="question"),
                OptionList("yes","no"),
                id = "body"
            ),
            resultview := Vertical(
                id = "status"
            )
        )
        body.can_focus = False
        resultview.can_focus = False
        self.body = body
        self.resultview = resultview


    async def ask_yes_no(self, text):
        await self.body.mount_all([
            Markdown("🧙 " + text, id="question"),
            query := OptionList(Option("yes"), Option("no"))
        ])
        query.focus()

    async def ask_string(self, text, placeholder=""):
        await self.body.mount_all([
            Markdown("🧙 " + text, id="question"),
            input := Input(placeholder=placeholder)
        ])
        input.focus()

    async def ask_file(self, text):
        await self.body.mount_all([
            Markdown("🧙 " + text, id="question"),
            tree := DirectoryTree("./")
        ])
        tree.focus()
        self.body.scroll_end(animate=False)

    async def set_stage(self, stage):
        match stage:
            case Stage.confirm_start: await self.set_confirm_start()
            case Stage.request_script_name: await self.set_request_script_name()
            case Stage.confirm_script_clobber: await self.set_confirm_script_clobber()
            case Stage.request_prepatched: await self.set_request_prepatched()
            case Stage.request_postpatched: await self.set_request_postpatched()
            case Stage.request_function_name: await self.set_request_function_name()
            case Stage.request_signature: await self.set_request_signature()
            case Stage.request_concolic: await self.set_request_concolic()
            case Stage.request_concolic_complete: await self.set_request_concolic_complete()
            case Stage.request_hooks: await self.set_request_hooks()
            case Stage.request_textual_report: await self.set_request_textual_report()
            case Stage.request_visualization: await self.set_request_visualization()
            case Stage.request_dump: await self.set_request_dump()
            case Stage.request_dump_name: await self.set_request_dump_name()
            case Stage.complete: await self.complete()
        self.stage = stage

    async def set_confirm_start(self):
        await self.ask_yes_no(
        "### Welcome to the Cozy Wizard!\n\n"
        "This wizard will ask you a few questions, and then set up a basic cozy project for you. Sound good?"
        )

    async def handle_confirm_start(self, message):
        if message.option_index == 0: 
            await self.set_stage(Stage.request_script_name)
        else: 
            exit()

    async def set_confirm_script_clobber(self):
        await self.ask_yes_no("That file already exists! Overwrite it?")

    async def handle_confirm_script_clobber(self, message):
        if message.option_index == 0:
            await self.set_stage(Stage.request_prepatched)
        else: 
            await self.set_stage(Stage.request_script_name)

    async def set_request_script_name(self):
        await self.ask_string(
        "OK! What filename would you like to give to your new cozy script?",
        placeholder="my-script.py"
        )

    async def handle_request_script_name(self,message):
        self.results.scriptname = message.value
        self.resultview.mount(Markdown("**Script Name:** " + message.value))
        if os.path.isfile(self.results.scriptname):
            await self.set_stage(Stage.confirm_script_clobber)
        else:
            await self.set_stage(Stage.request_prepatched)

    async def set_request_prepatched(self):
        await self.ask_file("Please locate the original unpatched binary")

    async def handle_request_prepatched(self, message):
        self.results.prepatched_path = message.path
        self.resultview.mount(Markdown("**Prepatched Binary:** " + str(message.path)))
        await self.set_stage(Stage.request_postpatched)

    async def set_request_postpatched(self):
        await self.ask_file("Please locate the patched binary")

    async def handle_request_postpatched(self, message):
        self.results.postpatched_path = message.path
        self.resultview.mount(Markdown("**Postpatched Binary:** " + str(message.path)))
        await self.set_stage(Stage.request_function_name)

    async def set_request_function_name(self):
        await self.ask_string(
        "Please enter the name or address of the function to be executed",
        placeholder="main"
        )

    async def handle_request_function_name(self, message):
        self.results.fun_name = message.value
        self.resultview.mount(Markdown("**Target Function:** " + str(message.value)))
        if message.value.startswith("0x") or message.value.isdigit():
            self.results.fun_name_processed = int(message.value, 16)
        else:
            self.results.fun_name_processed = message.value
        await self.set_stage(Stage.request_signature)

    async def set_request_signature(self):

        if isinstance(self.results.fun_name, int):
            await self.ask_string(
            "Please enter the function signature of the function at {}.".format(self.results.fun_name),
            placeholder="int main(int argc, char* argv[])"
            )
        else:
            await self.ask_string(
            "Please enter the function signature of the `{}` function.".format(self.results.fun_name),
            placeholder="int main(int argc, char* argv[])"
            )

    async def handle_request_signature(self, message):
        self.results.fun_signature = message.value
        self.resultview.mount(Markdown("**Function Signature:** " + str(message.value)))
        await self.set_stage(Stage.request_hooks)

    async def set_request_hooks(self):
        await self.ask_yes_no("Will you be using hooks to simulate hard to execute functions?")

    async def handle_request_hooks(self, message):
        self.results.hooks = message.option_index == 0
        self.resultview.mount(Markdown("**Use Hooks:** " + str(self.results.hooks)))
        await self.set_stage(Stage.request_concolic)

    async def set_request_concolic(self):
        await self.ask_yes_no(
        "Would you like to use concolic execution instead of typical symbolic execution while exploring?"
        )

    async def handle_request_concolic(self, message):
        self.results.concolic = message.option_index == 0
        self.resultview.mount(Markdown("**Use Concolic Evaluation:** " + str(self.results.concolic)))
        if self.results.concolic:
            await self.set_stage(Stage.request_concolic_complete)
        else:
            await self.set_stage(Stage.request_textual_report)

    async def set_request_concolic_complete(self):
        await self.ask_yes_no("Would you like to explore all possible states when performing concolic execution?")

    async def handle_request_concolic_complete(self, message):
        self.results.concolic_complete = message.option_index == 0
        self.resultview.mount(Markdown("**Complete Concolic Exploration:** " + str(self.results.concolic_complete)))
        await self.set_stage(Stage.request_textual_report)

    async def set_request_textual_report(self):
        await self.ask_yes_no("Would you like to output a textual version of the diff upon completion?")

    async def handle_request_textual_report(self, message):
        self.results.textual_report = message.option_index == 0
        self.resultview.mount(Markdown("**Create Textual Report:** " + str(self.results.textual_report)))
        await self.set_stage(Stage.request_dump)

    async def set_request_dump(self):
        await self.ask_yes_no(
        "Would you like to dump the results to a JSON file suitable for visualization in the future? "
        "Note that you can also save the results via the Files menu in the visualization interface."
        )

    async def handle_request_dump(self, message):
        self.results.dump = message.option_index == 0
        if self.results.dump:
            await self.set_stage(Stage.request_dump_name)
        else:
            await self.set_stage(Stage.request_visualization)

    async def set_request_dump_name(self):
        await self.ask_string("What should the JSON file be called?", placeholder="output.json")

    async def handle_request_dump_name(self, message):
        self.resultview.mount(Markdown("**JSON Report name:** " + message.value))

        self.results.dump_name = message.value
        await self.set_stage(Stage.request_visualization)

    async def set_request_visualization(self):
        await self.ask_yes_no(
        "Would you like to visualize the diff in a web browser, when cozy finishes analyzing the binaries?"
        )

    async def handle_request_visualization(self, message):
        self.results.visualize = message.option_index == 0
        self.resultview.mount(Markdown("**Launch Visualization:** " + str(self.results.visualize)))
        await self.set_stage(Stage.complete)

    async def complete(self):
        with open(self.results.scriptname, 'w') as f:
            f.write(self.results.to_string())
        exit()

    async def on_input_submitted(self, message: Input.Submitted) -> None:
        with self.app.batch_update():
            if message.value == "": 
                return
            else:
                await message.input.remove()
                await self.query_one("#question").remove()
                match self.stage:
                    case Stage.request_script_name: await self.handle_request_script_name(message)
                    case Stage.request_function_name: await self.handle_request_function_name(message)
                    case Stage.request_signature: await self.handle_request_signature(message)
                    case Stage.request_dump_name: await self.handle_request_dump_name(message)
    
    async def on_option_list_option_selected(self, message: OptionList.OptionSelected) -> None:
        with self.app.batch_update():
            await message.option_list.remove()
            await self.query_one("#question").remove()
            match self.stage:
                case Stage.confirm_start: await self.handle_confirm_start(message)
                case Stage.confirm_script_clobber: await self.handle_confirm_script_clobber(message)
                case Stage.request_concolic: await self.handle_request_concolic(message)
                case Stage.request_concolic_complete: await self.handle_request_concolic_complete(message)
                case Stage.request_hooks: await self.handle_request_hooks(message)
                case Stage.request_textual_report: await self.handle_request_textual_report(message)
                case Stage.request_visualization: await self.handle_request_visualization(message)
                case Stage.request_dump: await self.handle_request_dump(message)

    async def on_directory_tree_file_selected(self, message: DirectoryTree.FileSelected) -> None:
        with self.app.batch_update():
            await self.query_one("#question").remove()
            await message.control.remove()
            match self.stage:
                case Stage.request_prepatched: await self.handle_request_prepatched(message)
                case Stage.request_postpatched: await self.handle_request_postpatched(message)

if __name__ == "__main__":
    Wizard().run()
