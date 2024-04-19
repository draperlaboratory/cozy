import cozy
import claripy
import angr
from angr.procedures.linux_kernel.sysinfo import sysinfo_ty

onMessageLength_mangled = "_ZN3ros22TransportPublisherLink15onMessageLengthERKN5boost10shared_ptrINS_10ConnectionEEERKNS1_12shared_arrayIhEEjb"
connectionRead_mangled = "_ZN3ros10Connection4readEjRKN5boost8functionIFvRKNS1_10shared_ptrIS0_EERKNS1_12shared_arrayIhEEjbEEE"

onMessageLength_prototype = "void f(void *this, void *conn, void **buffer, unsigned int size, unsigned char success)"

proj_prepatched = cozy.project.Project("test_programs/amp_target3_hackathon/libroscpp.so")
proj_prepatched.add_prototype(onMessageLength_mangled, onMessageLength_prototype)

proj_attempted_patch = cozy.project.Project("test_programs/amp_target3_hackathon/libroscpp_manually_patched.so")
proj_attempted_patch.add_prototype(onMessageLength_mangled, onMessageLength_prototype)

proj_postpatched = cozy.project.Project("test_programs/amp_target3_hackathon/libroscpp-patcherex.so")
proj_postpatched.add_prototype(onMessageLength_mangled, onMessageLength_prototype)

proj_tob_patch = cozy.project.Project("test_programs/amp_target3_hackathon/libroscpp_tob.so")
proj_tob_patch.add_prototype(onMessageLength_mangled, onMessageLength_prototype)

proj_tob_no_fail_check_patch = cozy.project.Project("test_programs/amp_target3_hackathon/libroscpp_tob_no_fail_check.so")
proj_tob_no_fail_check_patch.add_prototype(onMessageLength_mangled, onMessageLength_prototype)

# size is a symbolic variable that ends up being passed to the onMessageLength function. This symbolic variable
# determines the size of the message that's going to be read. The goal is to make size be sufficiently small
# so we don't run out of memory allocating a block to store the incoming message
size = claripy.BVS("size", 32)

# This symbolic variable is stored inside the struct passed to a sysinfo call
totalram = claripy.BVS("totalram", 32)
freeram = claripy.BVS("freeram", 32)

sysinfo_succeded = claripy.BoolS("sysinfo_succeeded")

totalram_garbage = claripy.BVS("sysinfo_garbage_totalram", 32)
freeram_garbage = claripy.BVS("sysinfo_garbage_freeram", 32)

use_freeram = True

class connectionRead_hook(angr.SimProcedure):
    def run(self, this_conn, param_1, param_2):
        # Do nothing instead of executing the read method
        pass

class sysinfo_hook(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, is_syscall=True)

    def run(self, info):
        # The sysinfo syscall stores its results in the struct passed as a pointer to the syscall
        # here we use the default angr values, except for totalram, which we substitute with our symbolic
        # variable we created earlier
        value = {
            "uptime": 1234567,
            "loads": [20100, 22000, 15000],
            "totalram": claripy.ast.bool.If(sysinfo_succeded, totalram, totalram_garbage),
            "freeram": claripy.ast.bool.If(sysinfo_succeded, freeram, freeram_garbage),
            "sharedram": 1024 ** 2 // 4,
            "bufferram": 1024 ** 2 // 4,
            "totalswap": 1024 ** 2,
            "freeswap": 1024 ** 2 // 2,
            "procs": 533,
            "totalhigh": 11,
            "freehigh": 12,
            "mem_unit": 13,
        }
        sysinfo_ty.with_arch(self.arch).store(self.state, info, value)
        return claripy.ast.bool.If(sysinfo_succeded, claripy.BVV(0, 32), claripy.BVV(-1, 32))

proj_prepatched.hook_symbol(connectionRead_mangled, connectionRead_hook)
proj_prepatched.hook_syscall("sysinfo", sysinfo_hook)

proj_attempted_patch.hook_symbol(connectionRead_mangled, connectionRead_hook)
proj_postpatched.hook_syscall("sysinfo", sysinfo_hook)

proj_postpatched.hook_symbol(connectionRead_mangled, connectionRead_hook)
proj_postpatched.hook_syscall("sysinfo", sysinfo_hook)

proj_tob_patch.hook_symbol(connectionRead_mangled, connectionRead_hook)
#proj_tob_patch.angr_proj.hook(proj_tob_patch.find_symbol_addr(onMessageLength_mangled) + 0xF1458, sysinfo_hook())
#proj_tob_patch.angr_proj.hook(proj_tob_patch.find_symbol_addr("epoll_ctl") + 0x180, sysinfo_hook())
proj_tob_patch.hook_symbol("_ZNSt9basic_iosIcSt11char_traitsIcEE4initEPSt15basic_streambufIcS1_E", sysinfo_hook)

proj_tob_no_fail_check_patch.hook_symbol(connectionRead_mangled, connectionRead_hook)
proj_tob_no_fail_check_patch.hook_symbol("_ZNSt9basic_iosIcSt11char_traitsIcEE4initEPSt15basic_streambufIcS1_E", sysinfo_hook)

def run(sess):
    len_too_big = cozy.directive.ErrorDirective.from_fun_offset(sess.proj, onMessageLength_mangled, 0x10C, info_str="Requested size is too large!")
    sess.add_directives(len_too_big)

    # This assertion is placed in the branch where we call connection_->read(len, boost::bind(&TransportPublisherLink::onMessage, this, _1, _2, _3, _4));
    # The assertion will ensure that we aren't reading something from memory that's too big
    def totalram_exceeded_assert(state):
        if use_freeram:
            return size < freeram
        else:
            return size <= totalram
    totalram_exceeded = cozy.directive.Assert.from_fun_offset(sess.proj, onMessageLength_mangled, 0x1C8, totalram_exceeded_assert, info_str="Total RAM was exceeded")
    sess.add_directives(totalram_exceeded)

    # The buffer that contains the message we just read. Since we are exploring the path where we successfully read a length, use 4 bytes to store the length
    size_ptr = sess.malloc(0x4)
    sess.store(size_ptr, size, endness=proj_prepatched.arch.memory_endness)
    size_ptr_ptr = sess.malloc(4)
    sess.store(size_ptr_ptr, claripy.BVV(size_ptr, 32), endness=proj_prepatched.arch.memory_endness)
    this_obj = sess.malloc(0x100)
    # Set _retry_time_handler to be -1
    sess.store(this_obj + 0xb0, claripy.BVV(-1, 32), endness=proj_prepatched.arch.memory_endness)

    # Call onMessageLength(this_obj, NULL, size_ptr_ptr, 4, true)
    result = sess.run([this_obj, 0x0, size_ptr_ptr, 4, 1])

    print(result.report_asserts_failed({"size": size, "totalram": totalram, "freeram": freeram}))

    return result

def run_prepatched():
    print("Running prepatched with assertion that size <= totalram...")
    sess = proj_prepatched.session(onMessageLength_mangled)
    return run(sess)

def run_attempted_patch():
    print("Running attempted 'manual' patch with assertion that size <= totalram...")
    print("This patch was provided by the hackathon organizers, so if we get an assert triggered here, their attempted patch is incorrect.")
    sess = proj_attempted_patch.session(onMessageLength_mangled)
    return run(sess)

def run_postpatched():
    print("Running postpatched with assertion that size <= totalram...")
    sess = proj_postpatched.session(onMessageLength_mangled)
    return run(sess)

def run_tob_patched(proj):
    print("Running TOB postpatched")
    sess = proj.session(onMessageLength_mangled)

    #len_too_big = cozy.directive.ErrorDirective.from_fun_offset(sess.proj, onMessageLength_mangled, 0x1C8, info_str="Requested size is too large!")
    len_too_big = cozy.directive.ErrorDirective.from_fun_offset(sess.proj, onMessageLength_mangled, 0x10C,
                                                                info_str="Requested size is too large!")
    sess.add_directives(len_too_big)

    # This assertion is placed in the branch where we call connection_->read(len, boost::bind(&TransportPublisherLink::onMessage, this, _1, _2, _3, _4));
    # The assertion will ensure that we aren't reading something from memory that's too big
    def totalram_exceeded_assert(state):
        if use_freeram:
            return size < freeram
        else:
            return size <= totalram
    #totalram_exceeded = cozy.directive.Assert.from_fun_offset(sess.proj, onMessageLength_mangled, 0x10C, totalram_exceeded_assert, info_str="Total RAM was exceeded")
    totalram_exceeded = cozy.directive.Assert.from_fun_offset(sess.proj, onMessageLength_mangled, 0x1C8,
                                                              totalram_exceeded_assert,
                                                              info_str="Total RAM was exceeded")
    sess.add_directives(totalram_exceeded)

    # The buffer that contains the message we just read. Since we are exploring the path where we successfully read a length, use 4 bytes to store the length
    size_ptr = sess.malloc(0x4)
    sess.store(size_ptr, size, endness=sess.proj.arch.memory_endness)
    size_ptr_ptr = sess.malloc(4)
    sess.store(size_ptr_ptr, claripy.BVV(size_ptr, 32), endness=sess.proj.arch.memory_endness)
    this_obj = sess.malloc(0x100)
    # Set _retry_time_handler to be -1
    sess.store(this_obj + 0xb0, claripy.BVV(-1, 32), endness=sess.proj.arch.memory_endness)

    def bp(state):
        print(state)

    sess.add_directives(cozy.directive.Breakpoint.from_fun_offset(sess.proj, onMessageLength_mangled, 0x81268, bp))

    # Call onMessageLength(this_obj, NULL, size_ptr_ptr, 4, true)
    result = sess.run([this_obj, 0x0, size_ptr_ptr, 4, 1])

    print(result.report_asserts_failed({"size": size, "totalram": totalram, "freeram": freeram}))

    return result

pre_patched_results = run_prepatched()
attempted_patch_results = run_attempted_patch()
post_patched_results = run_postpatched()
tob_patched_results = run_tob_patched(proj_tob_patch)
tob_no_fail_check_results = run_tob_patched(proj_tob_no_fail_check_patch)

args = {"size": size, "totalram": totalram, "freeram": freeram, "sysinfo_freeram": freeram_garbage,
        "sysinfo_totalram": totalram_garbage, "sysinfo_succeeded": sysinfo_succeded}

comparison_results = cozy.analysis.Comparison(pre_patched_results, tob_no_fail_check_results)
print("\nComparison Results, pre-patch vs post-patch:\n")
print(comparison_results.report(args))

cozy.execution_graph.dump_comparison(proj_prepatched, proj_tob_no_fail_check_patch,
                                     pre_patched_results, tob_no_fail_check_results,
                                     comparison_results,
                                     "libroscpp.so", "libroscpp_tob_no_fail_check.so",
                                     "cozy-result_mrzr_no_fail_check.json",
                                     args=args, num_examples=2)
