# coding: utf-8
from cozy.project import Project
from cozy.analysis import Comparison
import cozy.execution_graph as execution_graph

import claripy

proj_pre = Project('test_programs/simple_branch/simpleBranch-pre')
proj_post = Project('test_programs/simple_branch/simpleBranch-post')

sess_pre = proj_pre.session("my_fun")
sess_post = proj_post.session("my_fun")

arg = claripy.BVS('n', 4 * 8)

rslt_pre = sess_pre.run([arg])
rslt_post = sess_post.run([arg])

comparison = Comparison(rslt_pre, rslt_post)

execution_graph.dump_comparison(proj_pre, proj_post, rslt_pre, rslt_post, comparison, output_file="cmp_simple_cond.json", args=[arg], num_examples=2, include_actions=True)
