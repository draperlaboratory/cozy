import angr.errors
import networkx as nx
import json
import sys
from angr.block import Block
from collections.abc import Callable
from .project import Project, TerminatedResult
from . import analysis
from .server import start_viz_server

def _serialize_diff(diff):
    for k,[v1,v2] in diff.items():
        diff[k] = [str(v1),str(v2)]
    return diff


def compare_and_dump(proj_a: Project, proj_b: Project,
                     rslt_a: TerminatedResult, rslt_b: TerminatedResult, 
                     file_name_a: str, file_name_b: str, 
                     concrete_arg_mapper: Callable [[any], any] | None = None, 
                     compare_memory: bool = True, compare_registers: bool = True,
                     include_vex: bool = False,
                     args: any = [], num_examples: int = 0):
    """
    Generates and saves JSON data for Cozy-Viz.

    Generates JSON data for Cozy-Viz from the results of two symbolic
    executions, and saves the result to two files, one for pre and one for post.

    :param Project proj_a: The project associated with the first execuction.
    :param Project proj_b: The project associated with the second execuction.
    :param TerminatedResult rslt_a: The result of the first execution.
    :param TerminatedResult rslt_b: The result of the second execution.
    :param str file_name_a: The filename for the JSON serializing the first execution
    :param str file_name_b: The filename for the JSON serializing the second execution
    :param Callable [[any],any] | None, optional concrete_arg_mapper: This function is used to
        post-process concretized versions of args before they are added to the
        return string. Some examples of this function include converting an integer
        to a negative number due to use of two's complement, or slicing off parts of
        the argument based on another part of the input arguments. Default None.
    :param bool, optional compare_memory: whether to, for each pair of
        corresponding dead-end states, compare memory contents and include any
        significant differences in the JSON. Default True.
    :param bool, optional compare_registers: whether to, for each pair of
        corresponding dead-end states, compare register contents and include
        any differences in the JSON. Default True.
    :param bool, optional include_vex: whether to, for each SimState, generate the
        corresponding VEX IR and include the result in the JSON. Default False.
    :param any, optional args: The input arguments to concretize. This argument
        may be a Python datastructure, the concretizer will make a deep copy with
        claripy symbolic variables replaced with concrete values. See
        :class:`cozy.analysis.PairComparison`. Default = [].
    :param int, optional num_examples: The number of concrete examples to
        generate and incorporate into the JSON, for each dead-end state. Default 0.
    """
    g_a, g_b = generate_comparison(proj_a, proj_b, rslt_a, rslt_b,
         concrete_arg_mapper=concrete_arg_mapper,
         compare_memory=compare_memory, 
         compare_registers=compare_registers,
         include_vex=include_vex,
         args=args, num_examples=num_examples)
    def write_graph(g, file_name):
        data = json.dumps(nx.cytoscape_data(g))
        with open(file_name, "w") as f:
            f.write(data)
    write_graph(g_a, file_name_a)
    write_graph(g_b, file_name_b)

def compare_and_viz(proj_a: Project, proj_b: Project,
                    rslt_a: TerminatedResult, rslt_b: TerminatedResult, 
                    concrete_arg_mapper: Callable [[any], any] | None = None, 
                    compare_memory: bool = True, compare_registers: bool = True,
                    include_vex: bool = False,
                    args: any = [], num_examples: int = 0,
                    open_browser=False, port=8080
                    ):
    """
    Generates and visualizes JSON data for Cozy-Viz.

    Generates JSON data suitable for visual comparison using Cozy-Viz from the \
    results of two symbolic executions, and launches a server to view the data.

    :param Project proj_a: The project associated with the first execuction.
    :param Project proj_b: The project associated with the second execuction.
    :param TerminatedResult rslt_a: The result of the first execution.
    :param TerminatedResult rslt_b: The result of the second execution.
    :param Callable [[any],any] | None, optional concrete_arg_mapper: This function is used to
        post-process concretized versions of args before they are added to the
        return string. Some examples of this function include converting an integer
        to a negative number due to use of two's complement, or slicing off parts of
        the argument based on another part of the input arguments. Default None.
    :param bool, optional compare_memory: whether to, for each pair of
        corresponding dead-end states, compare memory contents and include any
        significant differences in the JSON. Default True.
    :param bool, optional compare_registers: whether to, for each pair of
        corresponding dead-end states, compare register contents and include
        any differences in the JSON. Default True.
    :param bool, optional include_vex: whether to, for each SimState, generate the
        corresponding VEX IR and include the result in the JSON. Default False.
    :param any, optional args: The input arguments to concretize. This argument
        may be a Python datastructure, the concretizer will make a deep copy with
        claripy symbolic variables replaced with concrete values. See
        :class:`cozy.analysis.PairComparison`. Default [].
    :param int, optional num_examples: The number of concrete examples to
        generate and incorporate into the JSON, for each dead-end state. Default 0.
    :param bool, optional open_browser: Automatically open cozy-viz with the
        comparison data loaded. Default False.
    :param int, optional port: The port to serve cozy-viz on. Default 8080.
    """
    g_a, g_b = generate_comparison(proj_a, proj_b, rslt_a, rslt_b,
         concrete_arg_mapper=concrete_arg_mapper,
         compare_memory=compare_memory, 
         compare_registers=compare_registers,
         include_vex=include_vex,
         args=args, num_examples=num_examples)
    start_viz_server(json.dumps(nx.cytoscape_data(g_a)), json.dumps(nx.cytoscape_data(g_b)), open_browser=open_browser, port=port)

# TODO might want to have a class for proj/rslt/name triples or something
def generate_comparison(proj_a: Project, proj_b: Project, rslt_a:
                        TerminatedResult, rslt_b: TerminatedResult,
                        concrete_arg_mapper: Callable [[any], any] | None = None,
                        compare_memory: bool = True, compare_registers: bool = True,
                        include_vex: bool = False,
                        args: any = [], num_examples: int = 0):
    """
    Generates JSON data for Cozy-Viz.

    Generates JSON data suitable for visual comparison using Cozy-Viz from the \
    results of two symbolic executions.

    :param Project proj_a: The project associated with the first execuction.
    :param Project proj_b: The project associated with the second execuction.
    :param TerminatedResult rslt_a: The result of the first execution.
    :param TerminatedResult rslt_b: The result of the second execution.
    :param Callable [[any],any] | None, optional concrete_arg_mapper: This function is used to
        post-process concretized versions of args before they are added to the
        return string. Some examples of this function include converting an integer
        to a negative number due to use of two's complement, or slicing off parts of
        the argument based on another part of the input arguments. Default None.
    :param bool, optional compare_memory: whether to, for each pair of
        corresponding dead-end states, compare memory contents and include any
        significant differences in the JSON. Default True.
    :param bool, optional compare_registers: whether to, for each pair of
        corresponding dead-end states, compare register contents and include
        any differences in the JSON. Default True.
    :param bool, optional include_vex: whether to, for each SimState, generate the
        corresponding VEX IR and include the result in the JSON. Default False.
    :param any, optional args: The input arguments to concretize. This argument
        may be a Python datastructure, the concretizer will make a deep copy with
        claripy symbolic variables replaced with concrete values. See
        :class:`cozy.analysis.PairComparison`. Default = [].
    :param int, optional num_examples: The number of concrete examples to
        generate and incorporate into the JSON, for each dead-end state. Default 0.

    :return (networkx.DiGraph, networkx.DiGraph): A pair of directed graphs
        representing the two symbolic executions.
    """

    eg_a = ExecutionGraph(proj_a,rslt_a)
    eg_b = ExecutionGraph(proj_b,rslt_b)
    addrs_a = proj_a.object_ranges()
    addrs_b = proj_b.object_ranges()
    g_a = eg_a.reconstruct_bbl_addr_graph()
    g_b = eg_b.reconstruct_bbl_addr_graph()
    comparison_results = analysis.ComparisonResults(rslt_a,rslt_b, addrs_a + addrs_b,
                                                    compare_memory=compare_memory,
                                                    compare_registers=compare_registers,
                                                    # We extract std[out|err] below.
                                                    # But maybe we should get it from
                                                    # the analysis
                                                    compare_std_err=False,
                                                    compare_std_out=False)
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
            comp = comparison_results.pairs.get((state_a, state_b))
            if comp is not None:

                concretion = comp.concrete_examples(args, num_examples=num_examples)
                g_a.nodes[na]["compatibilities"][nb] = {
                        "memdiff": _serialize_diff(comp.mem_diff),
                        "regdiff": _serialize_diff(comp.reg_diff),
                        "conc_args": list(map(lambda x: concrete_arg_mapper(x.args), concretion))
                                     if concrete_arg_mapper is not None 
                                     else list(map(lambda x: x.args, concretion)),
                    }
                g_b.nodes[nb]["compatibilities"][na] = {
                        "memdiff": _serialize_diff(comp.mem_diff),
                        "regdiff": _serialize_diff(comp.reg_diff),
                        "conc_args": list(map(lambda x: concrete_arg_mapper(x.args), concretion))
                                     if concrete_arg_mapper is not None 
                                     else list(map(lambda x: x.args, concretion)),
                    }
    def stringify_attrs(eg, g):
        for (n, attr) in g.nodes.items():
            if include_vex: attr['vex'] = attr["contents"].vex._pp_str() or "*"
            attr['contents'] = eg._get_bbl_asm(attr["contents"]) or "*"
            attr['constraints'] = list(map(str, attr["constraints"])) or "*"
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
    :ivar TerminatedResult result: the result of the execution.
    """
    def __init__(self, proj: Project, result: TerminatedResult):
        self.proj = proj
        # TODO: if graph of states becomes too expensive, switch to graph of histories
        self.graph = nx.DiGraph()
        leaves = []
        for state in result.deadended:
            self.graph.add_node(state)
            leaves.append(state)
        for error_record in result.errored:
            msg = error_record.error.args[0]
            self.graph.add_node(error_record.state, error=msg)
            leaves.append(error_record.state)
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
