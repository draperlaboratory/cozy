import functools

import angr.errors
import claripy
import networkx as nx
import json
import sys

from angr import SimState
from angr.block import Block
from collections.abc import Callable

from angr.state_plugins import SimStateHistory

import cozy.analysis
from .functools_ext import fmap
from .project import Project
from .session import RunResult
from . import analysis
from .server import start_viz_server

def _serialize_diff(diff, nice_name_a: Callable[[int], str | None] | None = None, nice_name_b: Callable[[int], str | None] | None = None):
    def convert_key(k) -> str:
        if isinstance(k, range):
            ret = "{} .. {}".format(hex(k.start), hex(k.stop - 1))
            if nice_name_a is not None and nice_name_b is not None:
                nice_start_a = nice_name_a(k.start)
                nice_end_a = nice_name_a(k.stop - 1)
                nice_start_b = nice_name_b(k.start)
                nice_end_b = nice_name_b(k.stop - 1)
                if nice_start_a == nice_start_b and nice_end_a == nice_end_b:
                    if nice_start_a is not None or nice_end_a is not None:
                        ret += "\n{} .. {}".format(nice_start_a, nice_end_a)
                else:
                    if nice_start_a is not None or nice_end_a is not None or nice_start_b is not None or nice_end_b is not None:
                        ret += "\n{} .. {} (pre)".format(nice_start_a, nice_end_a)
                        ret += "\n{} .. {} (post)".format(nice_start_b, nice_end_b)
            return ret
        elif isinstance(k, int):
            return str(hex(k))
        else:
            return str(k)
    def convert_val(v) -> str:
        if isinstance(v, int):
            return str(hex(v))
        elif isinstance(v, claripy.ast.Bits):
            if v.symbolic:
                return v.shallow_repr(max_depth=3)
            else:
                return convert_val(v.concrete_value)
        else:
            return str(v)
    return {convert_key(k): (convert_val(v1), convert_val(v2)) for (k, (v1, v2)) in diff.items()}

def _serialized_field_diff(diff : any): 
    if isinstance(diff, analysis.EqFieldDiff):
        return {"tag": "fieldEq", "left": str(diff.left_body), "right": str(diff.right_body)}
    elif isinstance(diff, analysis.NotEqLeaf):
        return {"tag": "leafNeq", "left": str(diff.left_leaf), "right": str(diff.right_leaf)}
    elif isinstance(diff, analysis.NotEqFieldDiff):
        return fmap(diff.body_diff, _serialized_field_diff)
    else:
        # fmap into dict labels, so we need this default case too
        return str(diff)

def dump_comparison(proj_a: Project, proj_b: Project,
                    rslt_a: RunResult, rslt_b: RunResult,
                    comparison_results: analysis.Comparison,
                    file_name_a: str = "prepatch", file_name_b: str = "postpatch",
                    output_file: str = "cozy-result.json",
                    concrete_post_processor: Callable [[any], any] | None = None,
                    include_vex: bool = False, include_simprocs: bool = False,
                    flag_syscalls: bool = False, include_actions: bool = False,
                    include_debug: bool = False, include_side_effects: bool = True,
                    args: any = [], num_examples: int = 0) -> None:
    """
    Generates and saves JSON data for Cozy-Viz.

    Generates JSON data for Cozy-Viz from the results of two symbolic
    executions, and saves the result to two files, one for pre and one for post.

    :param Project proj_a: The project associated with the first execuction.
    :param Project proj_b: The project associated with the second execuction.
    :param RunResult rslt_a: The result of the first execution.
    :param RunResult rslt_b: The result of the second execution.
    :param analysis.Comparison comparison_results: The comparison we wish to dump.
    :param str, optional file_name_a: A name for the prepatch binary, displayed in visualization. 
        Default "prepatch".
    :param str, optional file_name_b: A name for the postpatch binary, displayed in visualization.
        Default "postpatch"
    :param str, optional output_file: A name for generated JSON file. Default "cozy-result.json".
    :param Callable [[any],any] | None, optional concrete_post_processor: This function is used to
        post-process concretized versions of args before they are added to the
        return string. Some examples of this function include converting an integer
        to a negative number due to use of two's complement, or slicing off parts of
        the argument based on another part of the input arguments. Default None.
    :param bool, optional include_vex: whether to, for each SimState, generate the
        corresponding VEX IR and include the result in the JSON. Default False.
    :param bool, optional include_simprocs: whether to, for each SimState, flag any
        SimProcedure locations occurring in the corrsponding basic block. Default False.
    :param bool, optional include_simprocs: whether to include a listing of
        SimProcedures called in each basic block. Default False.
    :param bool, optional include_actions: whether to include logging of
        read/write operations on memory and registers. Default False.
    :param bool, optional include_debug: whether to include debugging information
        recovered from DWARF metadata. Default False.
    :param bool, optional include_side_effects: whether to include cozy side effects,
        like virtual prints, if present. Default True.
    :param any, optional args: The input arguments to concretize. This argument
        may be a Python datastructure, the concretizer will make a deep copy with
        claripy symbolic variables replaced with concrete values. See
        :class:`cozy.analysis.CompatiblePair`. Default = [].
    :param int, optional num_examples: The number of concrete examples to
        generate and incorporate into the JSON, for each dead-end state. Default 0.
    """
    g_a, g_b = _generate_comparison(proj_a, proj_b, rslt_a, rslt_b, comparison_results,
                                    concrete_post_processor=concrete_post_processor,
                                    include_vex=include_vex,
                                    include_simprocs=include_simprocs,
                                    include_actions=include_actions,
                                    include_debug=include_debug,
                                    include_side_effects=include_side_effects,
                                    flag_syscalls=flag_syscalls,
                                    args=args, num_examples=num_examples)
    data = json.dumps({
        "pre" : {
            "name" : file_name_a,
            "data" : nx.cytoscape_data(g_a)
        },
        "post" : {
            "name" : file_name_b,
            "data" : nx.cytoscape_data(g_b)
        },
    })
    with open(output_file, "w") as f:
        f.write(data)

def visualize_comparison(proj_a: Project, proj_b: Project,
                         rslt_a: RunResult, rslt_b: RunResult,
                         comparison_results: analysis.Comparison,
                         concrete_post_processor: Callable [[any], any] | None = None,
                         include_vex: bool = False, include_simprocs: bool = False,
                         flag_syscalls: bool = False, include_actions: bool = False,
                         include_debug: bool = False, include_side_effects: bool = True,
                         args: any = [], num_examples: int = 0,
                         open_browser=False, port=8080
                         ):
    """
    Generates and visualizes JSON data for Cozy-Viz.

    Generates JSON data suitable for visual comparison using Cozy-Viz from the \
    results of two symbolic executions, and launches a server to view the data.

    :param Project proj_a: The project associated with the first execuction.
    :param Project proj_b: The project associated with the second execuction.
    :param RunResult rslt_a: The result of the first execution.
    :param RunResult rslt_b: The result of the second execution.
    :param analysis.Comparison comparison_results: The comparison we wish to dump.
    :param Callable [[any],any] | None, optional concrete_post_processor: This function is used to
        post-process concretized versions of args before they are added to the
        return string. Some examples of this function include converting an integer
        to a negative number due to use of two's complement, or slicing off parts of
        the argument based on another part of the input arguments. Default None.
    :param bool, optional include_vex: whether to, for each SimState, generate the
        corresponding VEX IR and include the result in the JSON. Default False.
    :param bool, optional include_simprocs: whether to include a listing of
        SimProcedures called in each basic block. Default False.
    :param bool, optional include_actions: whether to include logging of
        read/write operations on memory and registers. Default False.
    :param bool, optional include_debug: whether to include debugging information
        recovered from DWARF metadata. Default False.
    :param bool, optional include_side_effects: whether to include cozy side effects,
        like virtual prints, if present. Default True.
    :param any, optional args: The input arguments to concretize. This argument
        may be a Python datastructure, the concretizer will make a deep copy with
        claripy symbolic variables replaced with concrete values. See
        :class:`cozy.analysis.CompatiblePair`. Default [].
    :param int, optional num_examples: The number of concrete examples to
        generate and incorporate into the JSON, for each dead-end state. Default 0.
    :param bool, optional open_browser: Automatically open cozy-viz with the
        comparison data loaded. Default False.
    :param int, optional port: The port to serve cozy-viz on. Default 8080.
    """
    g_a, g_b = _generate_comparison(proj_a, proj_b, rslt_a, rslt_b, comparison_results,
                                    concrete_post_processor=concrete_post_processor,
                                    include_vex=include_vex,
                                    flag_syscalls=flag_syscalls,
                                    include_actions = include_actions,
                                    include_debug = include_debug,
                                    include_side_effects=include_side_effects,
                                    include_simprocs = include_simprocs,
                                    args=args, num_examples=num_examples)
    start_viz_server(json.dumps(nx.cytoscape_data(g_a)), json.dumps(nx.cytoscape_data(g_b)), open_browser=open_browser, port=port)

# TODO might want to have a class for proj/rslt/name triples or something
def _generate_comparison(proj_a: Project, proj_b: Project,
                         rslt_a: RunResult, rslt_b: RunResult,
                         comparison_results: analysis.Comparison,
                         concrete_post_processor: Callable [[any], any] | None = None,
                         include_vex: bool = False, include_simprocs: bool = False,
                         flag_syscalls: bool = False,
                         include_actions: bool = False,
                         include_debug: bool = False,
                         include_side_effects: bool = True,
                         args: any = [], num_examples: int = 0) -> tuple[nx.DiGraph, nx.DiGraph]:
    """
    Generates JSON data for Cozy-Viz.

    Generates JSON data suitable for visual comparison using Cozy-Viz from the \
    results of two symbolic executions.

    :param Project proj_a: The project associated with the first execuction.
    :param Project proj_b: The project associated with the second execuction.
    :param RunResult rslt_a: The result of the first execution.
    :param RunResult rslt_b: The result of the second execution.
    :param Callable [[any],any] | None, optional concrete_post_processor: This function is used to
        post-process concretized versions of args before they are added to the
        return string. Some examples of this function include converting an integer
        to a negative number due to use of two's complement, or slicing off parts of
        the argument based on another part of the input arguments. Default None.
    :param bool, optional include_vex: whether to, for each SimState, generate the
        corresponding VEX IR and include the result in the JSON. Default False.
    :param bool, optional include_simprocs: whether to include a listing of
        SimProcedures called in each basic block. Default False.
    :param bool, optional include_actions: whether to include logging of
        read/write operations on memory and registers. Default False.
    :param bool, optional include_debug: whether to include debugging information
        recovered from DWARF metadata. Default False.
    :param bool, optional include_side_effects: whether to include cozy side effects,
        like virtual prints, if present. Default True.
    :param any, optional args: The input arguments to concretize. This argument
        may be a Python datastructure, the concretizer will make a deep copy with
        claripy symbolic variables replaced with concrete values. See
        :class:`cozy.analysis.CompatiblePair`. Default = [].
    :param int, optional num_examples: The number of concrete examples to
        generate and incorporate into the JSON, for each dead-end state. Default 0.

    :return (networkx.DiGraph, networkx.DiGraph): A pair of directed graphs
        representing the two symbolic executions.
    """

    eg_a = ExecutionGraph(proj_a,rslt_a)
    eg_b = ExecutionGraph(proj_b,rslt_b)
    g_a = eg_a.reconstruct_bbl_addr_graph()
    g_b = eg_b.reconstruct_bbl_addr_graph()
    leaves_a = [v for (v, d) in g_a.out_degree() if d == 0]
    leaves_b = [v for (v, d) in g_b.out_degree() if d == 0]
    if include_debug:
        def attach_sourcemap(g, objs):
            root = [v for (v, d) in g.in_degree() if d == 0]
            sourcemap = {}
            for obj in objs: sourcemap.update(obj.addr_to_line)
            sourcemap = dict(map(lambda item: (item[0], list(item[1])), sourcemap.items()))
            g.nodes[root[0]]["debug"] = sourcemap
        attach_sourcemap(g_a, proj_a.angr_proj.loader.all_elf_objects)
        attach_sourcemap(g_b, proj_b.angr_proj.loader.all_elf_objects)
    for na in leaves_a:
        g_a.nodes[na]["compatibilities"] = {}
    for nb in leaves_b:
        g_b.nodes[nb]["compatibilities"] = {}
    for na in leaves_a:
        state_a = g_a.nodes[na]["state"]
        for nb in leaves_b:
            state_b = g_b.nodes[nb]["state"]
            if comparison_results.is_compatible(state_a, state_b):
                nice_name_a = functools.partial(cozy.analysis.nice_name, state_a, state_a.globals['malloced_names'])
                nice_name_b = functools.partial(cozy.analysis.nice_name, state_b, state_b.globals['malloced_names'])

                comp = comparison_results.get_pair(state_a, state_b)
                concretion = comp.concrete_examples(args, num_examples=num_examples)

                if concrete_post_processor is not None:
                    concrete_args = [concrete_post_processor(x.args) for x in concretion]
                else:
                    concrete_args = [x.args for x in concretion]

                def f(x):
                    if isinstance(x, claripy.ast.Bits):
                        return x.concrete_value
                    elif isinstance(x, claripy.ast.Bool):
                        return x.args[0]
                    else:
                        return x
                concrete_args = fmap(concrete_args, f)

                conc_sediff = []

                def serialize_conc_effect(effect, graph):
                    try:
                        id = [x for x,y in graph.nodes(data=True) if y["state"] == effect.state_history][0]
                        return { "id": id, "body": str(effect.mapped_body) }
                    except:
                        return { "body": str(effect.mapped_body) }

                for c in concretion:
                    channels = {}
                    for channel in c.left_side_effects:
                        channels[channel] = {
                            "left": list(map(lambda x: serialize_conc_effect(x, g_a), c.left_side_effects[channel])),
                            "right": list(map(lambda x: serialize_conc_effect(x, g_b), c.right_side_effects[channel]))
                        }
                    conc_sediff.append(channels)

                simplified_side_effect_diff = {}

                def serialize_abstract_effect(eff):
                    field1 = eff[0] != None
                    field2 = eff[1] != None
                    return [field1, field2, _serialized_field_diff(eff[2])]


                for channel in comp.side_effect_diff:
                    simplified_side_effect_diff[channel] = list(map(serialize_abstract_effect, comp.side_effect_diff[channel]))

                info = {
                    "sediff": simplified_side_effect_diff,
                    "memdiff": _serialize_diff(comp.mem_diff, nice_name_a, nice_name_b),
                    "regdiff": _serialize_diff(comp.reg_diff),
                    "conc_memdiff": [_serialize_diff(x.mem_diff, nice_name_a, nice_name_b) for x in concretion],
                    "conc_regdiff": [_serialize_diff(x.reg_diff) for x in concretion],
                    "conc_sediff" : conc_sediff,
                    "conc_args": concrete_args
                }
                g_a.nodes[na]["compatibilities"][nb] = info
                g_b.nodes[nb]["compatibilities"][na] = info

    def stringify_attrs(eg, g):
        for ((parent_i, child_i), edge_attr) in g.edges.items():
            child = g.nodes[child_i]["state"]
            parent = g.nodes[parent_i]["state"]
            if include_actions:
                edge_attr['actions'] = eg._list_actions(child,parent)
        for (n, attr) in g.nodes.items():
            if include_vex: attr['vex'] = attr["contents"].vex._pp_str() or "*"
            # FIXME: inefficient, we'll be running this many times for each basic block. 
            if include_simprocs: attr['simprocs'] = eg._list_simprocs(attr["contents"]) or []
            if flag_syscalls: attr['has_syscall'] = eg._has_syscall(attr["contents"]) or False
            attr['address'] = attr["state"].addr
            attr['contents'] = eg._get_bbl_asm(attr["contents"]) or "*"
            attr['constraints'] = [con.shallow_repr(max_depth=3) for con in attr["constraints"]] or "*"
            if "failed_cond" in attr: attr['failed_cond'] = str(attr["failed_cond"]) or "*"
            del attr['state']
    stringify_attrs(eg_a, g_a)
    stringify_attrs(eg_b, g_b)
    return (g_a, g_b)



class ExecutionGraph:
    """
    This class is used to store a `networkx.DiGraph`, decorated with \
    `SimStates`, representing the full history of a symbolic program execution. \

    It constructs an ExecutionGraph, from a project and the results of an
    executed project session.
    
    :ivar Project proj: the project associated with the execution.
    :ivar RunResult result: the result of the execution.
    """
    def __init__(self, proj: Project, result: RunResult):
        self.proj = proj
        # TODO: if graph of states becomes too expensive, switch to graph of histories
        self.graph = nx.DiGraph()
        leaves = []
        for deadended_state in result.deadended:
            state = deadended_state.state
            self.graph.add_node(state)
            leaves.append(state)
        for error_record in result.errored:
            msg = str(error_record.error)
            state = error_record.state
            self.graph.add_node(state, error=msg)
            leaves.append(state)
        for assert_fail_record in result.asserts_failed:
            cond = assert_fail_record.cond
            state = assert_fail_record.state
            assertion_info = assert_fail_record.assertion.info_str or "unlabled assertion"
            assertion_addr = assert_fail_record.assertion.addr
            self.graph.add_node(state, assertion_info=assertion_info, assertion_addr=assertion_addr, failed_cond=cond)
            leaves.append(state)
        for post_condition_record in result.postconditions_failed:
            cond = post_condition_record.cond
            state = post_condition_record.state
            assertion_info = post_condition_record.postcondition.info_str or "unlabled postcondition"
            self.graph.add_node(state, postcondition_info=assertion_info, failed_cond=cond)
            leaves.append(state)
        for spinning_record in result.spinning:
            state = spinning_record.state
            self.graph.add_node(state, spinning = True)
            leaves.append(state)
        for state in leaves:
            target = state
            for hist in reversed(list(state.history.parents)):
                source = hist
                self.graph.add_node(source)
                self.graph.add_edge(source, target)
                target = source

    def _get_bbl_asm(self, b : Block):
        """
        An internal method which renders the assembly corresponding to a given basic block as a formatted string

        :param Block b: The block to render.
        :return str: The rendered string.
        """
        try:
            addr = b.addr - 1 if b.thumb else b.addr
            return self.proj.angr_proj.analyses.Disassembly(
                    ranges=[(addr, addr + b.size)],
                    thumb=b.thumb,
                    block_bytes=b.bytes,
                    ).render(formatting={})
        except:
            return "*"

    def _list_simprocs(self, b : Block):
        # FIXME Need to document return type idiomatically, indicate possible None return
        """
        An internal method which lists SimProcedure calls occuring in a block

        :param Block b: the block to scan
        """
        try:
            addr = b.addr - 1 if b.thumb else b.addr
            procs = self.proj.angr_proj._sim_procedures
            sim_procs = []
            for a in range(addr, addr + b.size):
                if a in procs:
                    name = procs[a].display_name or print(procs[a])
                    home = procs[a].library_name

                    sim_procs.append(name + (" from " + home if home else ""))
            return sim_procs
        except:
            return None

    def _has_syscall(self, b : Block):
        # FIXME Need to indicate possible None return
        """
        An internal method which checks whether the jumpkind of a Block is
        a syscall.

        :param Block b: the relevant Block
        :return bool: Whether the jumpkind is a syscall
        """
        try:
            return b.vex.jumpkind.startswith("Ijk_Sys")
        except:
            return None

    def _list_actions(self, child: angr.SimState | SimStateHistory, parent: angr.SimState):
        # Actions are only recorded in history, not attached to the
        # SimState where they occurred. So we need to look at the history
        # of the child to get the actions occuring on the parent
        #
        # Different children may have different views of what actions their
        # parents took - for example if an action includes narrowing
        # a constraint. So we attach the actions a child associates with
        # their parent to an edge.
        if isinstance(child, angr.SimState):
            history = child.history
        else:
            history = child
        return list(map(str,filter(lambda x: x.bbl_addr == history.addr, history.actions)))

    def reconstruct_bbl_addr_graph(self):
        """
        Convert the SimState-decorated graph into a graph decorated with
        integers, carrying symbolic program execution data in the attributes
        `stdout`, `stderr`, `contents` (this holds a basic block),
        `constraints`, `actions` (optionally) and `state`.

        :return networkx.DiGraph: The resulting graph.
        """
        g = nx.convert_node_labels_to_integers(self.graph, label_attribute='state')
        for (node_i, attr) in g.nodes.items():
            # Note that the data used by this function is saved in cozy.session._save_states
            node_history = g.nodes[node_i]['state']
            if isinstance(node_history, SimState):
                node_history = node_history.history

            stdout = node_history.cozy_stdout
            try:
                attr['stdout'] = stdout.decode('utf-8')
            except UnicodeDecodeError:
                attr['stdout'] = str(stdout)

            stderr = node_history.cozy_stderr
            try:
                attr['stderr'] = stderr.decode('utf-8')
            except UnicodeDecodeError:
                attr['stderr'] = str(stderr)

            attr['contents'] = node_history.cozy_contents
            attr['constraints'] = node_history.cozy_constraints
        return g

    def reconstruct_bbl_pp_graph(self):
        """
        Convert the SimState-decorated graph into a graph decorated with
        integers, carrying symbolic program execution data in the attributes
        `stdout`, `stderr`, `contents`, `constraints` ,`vex` and `state`. The
        difference from :func:`reconstruct_bbl_addr_graph` is that the data is
        now pretty-printed and suitable for serialization.

        :return networkx.DiGraph: The resulting graph.
        """
        g = self.reconstruct_bbl_addr_graph()
        for n,attr in g.nodes.items():
            attr['contents'] = self._get_bbl_asm(attr["contents"]) or "*"
            attr['vex'] = attr["contents"].vex._pp_str() or "*"
            attr['constraints'] = list(map(str, attr["constraints"])) or "*"
            del attr['state']
        return g

    def dump_bbp_pp_cytoscape(self, name: str):
        """
        Dump the graph as cytoscapejs readable JSON.

        :param str name: The filename for the generated json.
        """
        g = self.reconstruct_bbl_pp_graph()
        data = json.dumps(nx.cytoscape_data(g), default=vars)
        with open(name, "w") as f:
            f.write(data)
