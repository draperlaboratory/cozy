import claripy
import cozy.analysis as analysis
import cozy.claripy_ext as claripy_ext
from cozy.directive import Assume
from cozy.project import Project
from cozy.constants import *
import cozy.primitives as primitives

pre_proj = Project('test_programs/buff_overflow/buff_overflow')
pre_sess = pre_proj.session('patch_fun', underconstrained_execution=True)
pre_patched = pre_sess.run()

post_proj = Project('test_programs/buff_overflow/buff_overflow_patched')
post_sess = post_proj.session('patch_fun', underconstrained_execution=True)
post_patched = post_sess.run()

comparison_results = analysis.Comparison(pre_patched, post_patched)
print(comparison_results.report([]))