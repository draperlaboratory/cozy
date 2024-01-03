# coding: utf-8
from cozy.project import Project
from cozy.analysis import Comparison
import cozy.execution_graph as execution_graph

import claripy

proj_pre = Project('test_programs/simple_branch/simpleBranch-pre')

proj_post = Project('test_programs/simple_branch/simpleBranch-post')

sess_pre = proj_pre.session("main")

sess_post = proj_post.session("main")

arg = claripy.BVS('n', 4 * 8)

rslt_pre = sess_pre.run(arg, cache_intermediate_states=True)

rslt_post = sess_post.run(arg, cache_intermediate_states=True)

comparison = Comparison(rslt_pre, rslt_post)

#execution_graph.dump_comparison(proj_pre, proj_post, rslt_pre, rslt_post, comparison, "simple_pre.json","simple_post.json", args=[arg])
execution_graph.visualize_comparison(proj_pre, proj_post, rslt_pre, rslt_post, comparison, args=[arg], num_examples=2, open_browser=True)
