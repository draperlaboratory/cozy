import os
from enum import Enum
from textual.app import App, ComposeResult
from textual.widgets import OptionList, Markdown, Input, DirectoryTree
from textual.containers import VerticalScroll
from textual.message import Message

class Results():
    pass

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
    confirm_dump_clobber = 15

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
        self.body = VerticalScroll()
        yield self.body
        self.set_stage(Stage.confirm_start)

    def ask_yes_no(self, text):
        query = OptionList("yes","no")
        self.body.mount(Markdown(text))
        self.body.mount(query)
        query.focus()

    def ask_string(self, text):
        self.body.mount(Markdown(text))
        input = Input()
        self.body.mount(input)
        input.focus()

    def ask_file(self, text):
        self.body.mount(Markdown(text))
        tree = DirectoryTree("./")
        self.body.mount(tree)
        tree.focus()

    def set_stage(self, stage):
        if self.body._allow_scroll: self.body.scroll_end(animate=False, force=True)
        match stage:
            case Stage.confirm_start: self.set_confirm_start()
            case Stage.request_script_name: self.set_request_script_name()
            case Stage.confirm_script_clobber: self.set_confirm_script_clobber()
            case Stage.request_prepatched: self.set_request_prepatched()
            case Stage.request_postpatched: self.set_request_postpatched()
            case Stage.request_function_name: self.set_request_function_name()
            case Stage.request_signature: self.set_request_signature()
            case Stage.request_concolic: self.set_request_concolic()
            case Stage.request_concolic_complete: self.set_request_concolic_complete()
            case Stage.request_hooks: self.set_request_hooks()
            case Stage.request_textual_report: self.set_request_textual_report()
            case Stage.request_visualization: self.set_request_visualization()
            case Stage.request_dump: self.set_request_dump()
            case Stage.request_dump_name: self.set_request_dump_name()
            case Stage.confirm_dump_clobber: self.set_confirm_dump_clobber()
        self.stage = stage

    def set_request_prepatched(self):
        pass

    def set_confirm_start(self):
        self.ask_yes_no(
        "### Welcome to the Cozy Wizard!\n\n"
        "This wizard will ask you a few questions, and then set up a basic cozy project for you. Sound good?"
        )

    def handle_confirm_start(self, message):
        message.option_list.remove()
        if message.option_index == 0: 
            self.set_stage(Stage.request_script_name)
        else: 
            exit()

    def set_confirm_script_clobber(self):
        self.ask_yes_no("That file already exists! Overwrite it?")

    def handle_confirm_script_clobber(self, message):
        message.option_list.remove()
        if message.option_index == 0:
            self.set_stage(Stage.request_prepatched)
        else: 
            self.set_stage(Stage.request_script_name)

    def set_request_script_name(self):
        self.ask_string(
        "OK! What filename would you like to give to your new cozy script?"
        )

    def handle_request_script_name(self,message):
        self.results.scriptname = message.value
        message.input.remove()
        if os.path.isfile(self.results.scriptname):
            self.set_stage(Stage.confirm_script_clobber)
        else:
            self.set_stage(Stage.request_prepatched)

    def set_request_prepatched(self):
        self.ask_file("Please locate the original unpatched binary")

    def handle_request_prepatched(self, message):
        message.control.remove()
        self.results.prepatched_path = message.path
        self.set_stage(Stage.request_postpatched)

    def set_request_postpatched(self):
        self.ask_file("Please locate the patched binary")

    def handle_request_postpatched(self, message):
        message.control.remove()
        self.results.postpatched_path = message.path
        self.set_stage(Stage.request_function_name)

    def set_request_function_name(self):
        self.ask_string("Please enter the name or address of the function to be executed")

    def handle_request_function_name(self, message):
        if message.value.startswith("0x"):
            self.results.fun_name = int(message.value, 16)
        elif message.value.isdigit():
            self.results.fun_name = int(message.value, 16)
        else:
            self.results.fun_name = message.value
        message.input.remove()
        self.set_stage(Stage.request_signature)

    def set_request_signature(self):

        if isinstance(self.results.fun_name, int):
            self.ask_string(
            "Please enter the function signature of the function at {}.".format(self.results.fun_name)
            )
        else:
            self.ask_string(
            "Please enter the function signature of the `{}` function.".format(self.results.fun_name)
            )

    def handle_request_signature(self, message):
        message.input.remove()
        self.results.fun_signature = message.value
        self.set_stage(Stage.request_hooks)

    def set_request_hooks(self):
        self.ask_yes_no("Will you be using hooks to simulate hard to execute functions?")

    def handle_request_hooks(self, message):
        self.results.hooks = message.option_index == 0
        message.option_list.remove()
        self.set_stage(Stage.request_concolic)

    def set_request_concolic(self):
        self.ask_yes_no("Would you like to use concolic execution instead of typical symbolic execution while exploring?")

    def handle_request_concolic(self, message):
        self.results.concolic = message.option_index == 0
        message.option_list.remove()
        if self.results.concolic:
            self.set_stage(Stage.request_concolic_complete)
        else:
            self.set_stage(Stage.request_textual_report)

    def set_request_concolic_complete(self):
        self.ask_yes_no("Would you like to explore all possible states when performing concolic execution?")

    def handle_request_concolic_complete(self, message):
        self.results.concolic_complete = message.option_index == 0
        message.option_list.remove()
        self.set_stage(Stage.request_textual_report)

    def set_request_textual_report(self):
        self.ask_yes_no("Would you like to output a textual version of the diff upon completion?")

    def handle_request_textual_report(self, message):
        self.results.textual_report = message.option_index == 0
        message.option_list.remove()
        self.set_stage(Stage.request_dump)

    def set_request_dump(self):
        self.ask_yes_no(
        "Would you like to dump the results to a JSON file suitable for visualization in the future? "
        "Note that you can also save the results via the Files menu in the visualization interface."
        )

    def handle_request_dump(self, message):
        self.results.dump = message.option_index == 0
        message.option_list.remove()
        if self.results.dump:
            self.set_stage(Stage.request_dump_name)
        else:
            self.set_stage(Stage.request_visualization)

    def set_request_dump_name(self):
        self.ask_string("What should the JSON file be called?")

    def handle_request_dump_name(self, message):
        self.results.dump_name = message.value
        message.input.remove()
        self.set_stage(Stage.request_visualization)

    def set_request_visualization(self):
        self.ask_yes_no("Would you like to visualize the diff in a web browser, when cozy finishes analyzing the binaries?")

    def handle_request_visualization(self, message):
        self.results.visualize = message.option_index == 0
        message.option_list.remove()

    def on_input_submitted(self, message: Input.Submitted) -> None:
        match self.stage:
            case Stage.request_script_name: self.handle_request_script_name(message)
            case Stage.request_function_name: self.handle_request_function_name(message)
            case Stage.request_signature: self.handle_request_signature(message)
            case Stage.request_dump_name: self.handle_request_dump_name(message)
    
    def on_option_list_option_selected(self, message: OptionList.OptionSelected) -> None:
        match self.stage:
            case Stage.confirm_start: self.handle_confirm_start(message)
            case Stage.confirm_script_clobber: self.handle_confirm_script_clobber(message)
            case Stage.request_concolic: self.handle_request_concolic(message)
            case Stage.request_concolic_complete: self.handle_request_concolic_complete(message)
            case Stage.request_hooks: self.handle_request_hooks(message)
            case Stage.request_textual_report: self.handle_request_textual_report(message)
            case Stage.request_visualization: self.handle_request_visualization(message)
            case Stage.request_dump: self.handle_request_dump(message)
            case Stage.confirm_dump_clobber: self.handle_confirm_dump_clobber(message)

    def on_directory_tree_file_selected(self, message: DirectoryTree.FileSelected) -> None:
        match self.stage:
            case Stage.request_prepatched: self.handle_request_prepatched(message)
            case Stage.request_postpatched: self.handle_request_postpatched(message)

if __name__ == "__main__":
    Wizard().run()
