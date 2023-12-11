import angr.errors
import networkx as nx
import json
import sys
from angr.block import Block
from collections.abc import Callable
from .project import Project, RunResult
from . import analysis
from .server import start_viz_server

def _serialize_diff(diff):
    def convert_key(k) -> str:
        if isinstance(k, range):
            return "{} .. {}".format(hex(k.start), hex(k.stop - 1))
        elif isinstance(k, int):
            return str(hex(k))
        else:
            return str(k)
    def convert_val(v) -> str:
        if isinstance(v, int):
            return str(hex(v))
        else:
            return str(v)
    return {convert_key(k): (convert_val(v1), convert_val(v2)) for (k, (v1, v2)) in diff.items()}

def dump_comparison(proj_a: Project, proj_b: Project,
                    rslt_a: RunResult, rslt_b: RunResult,
                    comparison_results: analysis.Comparison,
                    file_name_a: str, file_name_b: str,
                    concrete_arg_mapper: Callable [[any], any] | None = None,
                    include_vex: bool = False, include_simprocs: bool = False,
                    flag_syscalls: bool = False,
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
    :param str file_name_a: The filename for the JSON serializing the first execution
    :param str file_name_b: The filename for the JSON serializing the second execution
    :param Callable [[any],any] | None, optional concrete_arg_mapper: This function is used to
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
    :param any, optional args: The input arguments to concretize. This argument
        may be a Python datastructure, the concretizer will make a deep copy with
        claripy symbolic variables replaced with concrete values. See
        :class:`cozy.analysis.CompatiblePair`. Default = [].
    :param int, optional num_examples: The number of concrete examples to
        generate and incorporate into the JSON, for each dead-end state. Default 0.
    """
    g_a, g_b = _generate_comparison(proj_a, proj_b, rslt_a, rslt_b, comparison_results,
                                    concrete_arg_mapper=concrete_arg_mapper,
                                    include_vex=include_vex,
                                    include_simprocs=include_simprocs,
                                    flag_syscalls=flag_syscalls,
                                    args=args, num_examples=num_examples)
    def write_graph(g, file_name):
        data = json.dumps(nx.cytoscape_data(g))
        with open(file_name, "w") as f:
            f.write(data)
    write_graph(g_a, file_name_a)
    write_graph(g_b, file_name_b)

def visualize_comparison(proj_a: Project, proj_b: Project,
                         rslt_a: RunResult, rslt_b: RunResult,
                         comparison_results: analysis.Comparison,
                         concrete_arg_mapper: Callable [[any], any] | None = None,
                         include_vex: bool = False, include_simprocs: bool = False,
                         flag_syscalls: bool = False,
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
    :param Callable [[any],any] | None, optional concrete_arg_mapper: This function is used to
        post-process concretized versions of args before they are added to the
        return string. Some examples of this function include converting an integer
        to a negative number due to use of two's complement, or slicing off parts of
        the argument based on another part of the input arguments. Default None.
    :param bool, optional include_vex: whether to, for each SimState, generate the
        corresponding VEX IR and include the result in the JSON. Default False.
    :param bool, optional include_simprocs: whether to include a listing of
        SimProcedures called in each basic block. Default False.
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
                                    concrete_arg_mapper=concrete_arg_mapper,
                                    include_vex=include_vex,
                                    flag_syscalls=flag_syscalls,
                                    include_simprocs = include_simprocs,
                                    args=args, num_examples=num_examples)
    start_viz_server(json.dumps(nx.cytoscape_data(g_a)), json.dumps(nx.cytoscape_data(g_b)), open_browser=open_browser, port=port)

# TODO might want to have a class for proj/rslt/name triples or something
def _generate_comparison(proj_a: Project, proj_b: Project,
                         rslt_a: RunResult, rslt_b: RunResult,
                         comparison_results: analysis.Comparison,
                         concrete_arg_mapper: Callable [[any], any] | None = None,
                         include_vex: bool = False, include_simprocs: bool = False,
                         flag_syscalls: bool = False,
                         args: any = [], num_examples: int = 0) -> tuple[nx.DiGraph, nx.DiGraph]:
    """
    Generates JSON data for Cozy-Viz.

    Generates JSON data suitable for visual comparison using Cozy-Viz from the \
    results of two symbolic executions.

    :param Project proj_a: The project associated with the first execuction.
    :param Project proj_b: The project associated with the second execuction.
    :param RunResult rslt_a: The result of the first execution.
    :param RunResult rslt_b: The result of the second execution.
    :param Callable [[any],any] | None, optional concrete_arg_mapper: This function is used to
        post-process concretized versions of args before they are added to the
        return string. Some examples of this function include converting an integer
        to a negative number due to use of two's complement, or slicing off parts of
        the argument based on another part of the input arguments. Default None.
    :param bool, optional include_vex: whether to, for each SimState, generate the
        corresponding VEX IR and include the result in the JSON. Default False.
    :param bool, optional include_simprocs: whether to include a listing of
        SimProcedures called in each basic block. Default False.
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
    for na in leaves_a:
        g_a.nodes[na]["compatibilities"] = {}
    for nb in leaves_b:
        g_b.nodes[nb]["compatibilities"] = {}
    for na in leaves_a:
        state_a = g_a.nodes[na]["state"]
        for nb in leaves_b:
            state_b = g_b.nodes[nb]["state"]
            if comparison_results.is_compatible(state_a, state_b):
                comp = comparison_results.get_pair(state_a, state_b)
                concretion = comp.concrete_examples(args, num_examples=num_examples)
                g_a.nodes[na]["compatibilities"][nb] = {
                        "memdiff": _serialize_diff(comp.mem_diff),
                        "regdiff": _serialize_diff(comp.reg_diff),
                        "conc_memdiff": list(map(lambda x: _serialize_diff(x.mem_diff), concretion)),
                        "conc_regdiff": list(map(lambda x: _serialize_diff(x.reg_diff), concretion)),
                        "conc_args": list(map(lambda x: concrete_arg_mapper(x.args), concretion))
                                     if concrete_arg_mapper is not None 
                                     else list(map(lambda x: x.args, concretion)),
                    }
                g_b.nodes[nb]["compatibilities"][na] = {
                        "memdiff": _serialize_diff(comp.mem_diff),
                        "regdiff": _serialize_diff(comp.reg_diff),
                        "conc_memdiff": list(map(lambda x: _serialize_diff(x.mem_diff), concretion)),
                        "conc_regdiff": list(map(lambda x: _serialize_diff(x.reg_diff), concretion)),
                        "conc_args": list(map(lambda x: concrete_arg_mapper(x.args), concretion))
                                     if concrete_arg_mapper is not None 
                                     else list(map(lambda x: x.args, concretion)),
                    }
    def stringify_attrs(eg, g):
        for (n, attr) in g.nodes.items():
            if include_vex: attr['vex'] = attr["contents"].vex._pp_str() or "*"
            # FIXME: inefficient, we'll be running this many times for each basic block. 
            if include_simprocs: attr['simprocs'] = eg._list_simprocs(attr["contents"]) or []
            if flag_syscalls: attr['has_syscall'] = eg._has_syscall(attr["contents"]) or False
            attr['contents'] = eg._get_bbl_asm(attr["contents"]) or "*"
            attr['constraints'] = list(map(str, attr["constraints"])) or "*"
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
        for state in leaves:
            target = state
            for hist in reversed(list(state.history.parents)):
                if hasattr(hist, "custom_strongref_state"):
                    source = hist.custom_strongref_state
                else:
                    raise AttributeError("An input state did not have the 'custom_strongref_state' attribute. Did you forget to enable caching of intermediate states when running a session?")
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

    def reconstruct_bbl_addr_graph(self):
        """
        Convert the SimState-decorated graph into a graph decorated with
        integers, carrying symbolic program execution data in the attributes
        `stdout`, `stderr`, `contents` (this holds a basic block),
        `constraints` and `state`.

        :return networkx.DiGraph: The resulting graph.
        """
        g = nx.convert_node_labels_to_integers(self.graph, label_attribute='state')
        for ((parent_i, child_i), edge_attr) in g.edges.items():
            parent_state = g.nodes[parent_i]['state']
            child_state = g.nodes[child_i]['state']
        for (node_i, attr) in g.nodes.items():
            node = g.nodes[node_i]['state']
            # Assuming utf-8 character encoding, 
            attr['stdout'] = node.posix.dumps(sys.stdout.fileno()).decode('utf-8')
            attr['stderr'] = node.posix.dumps(sys.stderr.fileno()).decode('utf-8')
            if node.project.simos.is_syscall_addr(node.addr):
                # Here we are inside of a syscall implementation. The address that
                # angr jumps to when it executes a syscall does not actually contain
                # the code that is executed. Instead a Python hook is executed
                # to simulate the syscall.
                attr['contents'] = ""
            else:
                try:
                    attr['contents'] = node.block()
                except angr.errors.SimEngineError as exc:
                    attr['contents'] = ""
            attr['constraints'] = node.solver.constraints
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
        data = json.dumps(nx.cytoscape_data(g))
        with open(name, "w") as f:
            f.write(data)
