# coding: utf-8
from cozy.project import Project
from cozy.analysis import Comparison
import cozy.execution_graph as execution_graph

import claripy

proj_pre = Project('test_programs/simple_branch/simpleBranch-pre')
proj_post = Project('test_programs/simple_branch/simpleBranch-post')

sess_pre = proj_pre.session("my_fun", underconstrained_execution=True)
sess_post = proj_post.session("my_fun", underconstrained_execution=True)

rslt_pre = sess_pre.run()
rslt_post = sess_post.run()

comparison = Comparison(rslt_pre, rslt_post)

execution_graph.visualize_comparison(proj_pre, proj_post, rslt_pre, rslt_post, comparison, args=[], num_examples=2, open_browser=True, include_actions=True)
