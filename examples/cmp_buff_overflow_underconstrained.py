import claripy
import cozy.analysis as analysis
import cozy.claripy_ext as claripy_ext
from cozy.directive import Assume
from cozy.project import Project
from cozy.constants import *
import cozy.primitives as primitives

pre_proj = Project('test_programs/buff_overflow/buff_overflow')
pre_sess = pre_proj.session('patch_fun', underconstrained_execution=True)
pre_patched_results = pre_sess.run()

post_proj = Project('test_programs/buff_overflow/buff_overflow_patched')
post_sess = post_proj.session('patch_fun', underconstrained_execution=True,
                              underconstrained_initial_state=pre_patched_results.underconstrained_machine_state)
post_patched_results = post_sess.run()

comparison_results = analysis.Comparison(pre_patched_results, post_patched_results)
print(comparison_results.report(post_patched_results.underconstrained_machine_state.args))