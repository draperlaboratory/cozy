import networkx as nx
import json
import sys
from . import analysis

def serialize_diff(diff):
    for k,[v1,v2] in diff.items():
        diff[k] = [str(v1),str(v2)]
    return diff

# TODO might want to have a class for proj/rslt/name triples or something
def compare_and_dump(proj_a, proj_b, rslt_a, rslt_b, file_name_a, file_name_b, 
                     concrete_arg_mapper=None, compare_memory=True, compare_registers=True,
                     include_vex=False,
                     args=[], num_examples=0):

    eg_a = ExecutionGraph(proj_a,rslt_a)
    eg_b = ExecutionGraph(proj_b,rslt_b)
    addrs_a = proj_a.object_ranges()
    addrs_b = proj_b.object_ranges()
    g_a = eg_a.reconstruct_bbl_addr_graph()
    g_b = eg_b.reconstruct_bbl_addr_graph()
    comparison_results = analysis.compare_states(rslt_a,rslt_b, addrs_a + addrs_b,
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
                        "memdiff": serialize_diff(comp.mem_diff),
                        "regdiff": serialize_diff(comp.reg_diff),
                        "conc_args": list(map(lambda x: concrete_arg_mapper(x.args), concretion))
                                     if concrete_arg_mapper is not None 
                                     else list(map(lambda x: x.args, concretion)),
                    }
                g_b.nodes[nb]["compatibilities"][na] = {
                        "memdiff": serialize_diff(comp.mem_diff),
                        "regdiff": serialize_diff(comp.reg_diff),
                        "conc_args": list(map(lambda x: concrete_arg_mapper(x.args), concretion))
                                     if concrete_arg_mapper is not None 
                                     else list(map(lambda x: x.args, concretion)),
                    }
    def stringify_attrs(eg, g):
        for (n, attr) in g.nodes.items():
            if include_vex: attr['vex'] = attr["contents"].vex._pp_str() or "*"
            attr['contents'] = eg.get_bbl_asm(attr["contents"]) or "*"
            attr['constraints'] = list(map(str, attr["constraints"])) or "*"
            del attr['state']
    stringify_attrs(eg_a, g_a)
    stringify_attrs(eg_b, g_b)
    def write_graph(g, file_name):
        data = json.dumps(nx.cytoscape_data(g))
        with open(file_name, "w") as f:
            f.write(data)
    write_graph(g_a, file_name_a)
    write_graph(g_b, file_name_b)



class ExecutionGraph:
    def __init__(self, proj, result):
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

    def get_bbl_asm(self, b):
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
        g = nx.convert_node_labels_to_integers(self.graph, label_attribute='state')
        for ((parent_i, child_i), edge_attr) in g.edges.items():
            parent_state = g.nodes[parent_i]['state']
            child_state = g.nodes[child_i]['state']
        for (node_i, attr) in g.nodes.items():
            node = g.nodes[node_i]['state']
            # Assuming utf-8 character encoding, 
            attr['stdout'] = node.posix.dumps(sys.stdout.fileno()).decode('utf-8')
            attr['stderr'] = node.posix.dumps(sys.stderr.fileno()).decode('utf-8')
            attr['contents'] = node.block()
            attr['constraints'] = node.solver.constraints
        return g

    def reconstruct_bbl_pp_graph(self):
        g = self.reconstruct_bbl_addr_graph()
        for n,attr in g.nodes.items():
            attr['contents'] = self.get_bbl_asm(attr["contents"]) or "*"
            attr['vex'] = attr["contents"].vex._pp_str() or "*"
            attr['constraints'] = list(map(str, attr["constraints"])) or "*"
            del attr['state']
        return g

    def dump_bbp_pp_cytoscape(self, name):
        g = self.reconstruct_bbl_pp_graph()
        data = json.dumps(nx.cytoscape_data(g))
        with open(name, "w") as f:
            f.write(data)
