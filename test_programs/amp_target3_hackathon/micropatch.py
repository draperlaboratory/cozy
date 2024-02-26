import patcherex2

def get_patch_location(proj):
    onMessageLength_mangled = "_ZN3ros22TransportPublisherLink15onMessageLengthERKN5boost10shared_ptrINS_10ConnectionEEERKNS1_12shared_arrayIhEEjb"
    onMessageLengthStart = proj.binary_analyzer.get_function(onMessageLength_mangled)['addr']
    offset = 0xf8
    return onMessageLengthStart + offset

def apply_nops():
    proj = patcherex2.Patcherex("libroscpp.so")
    instruction_addr = get_patch_location(proj)
    proj.patches.append(patcherex2.RemoveInstructionPatch(instruction_addr, num_bytes=8, num_instr=2))

    proj.apply_patches()
    proj.binfmt_tool.save_binary("libroscpp-patcherex-noped.so")

def apply_micropatch():
    proj = patcherex2.Patcherex("libroscpp-patcherex-noped.so")

    sysinfo_asm = '''
    @ Save r0 and r7 since we're clobbering them
    push {r0,r7}
    @ Make space on the stack for the sysinfo struct
    sub sp, sp, #68
    @ #116 means we're going to make a sysinfo syscall
    mov r7, #116
    @ Move the sysinfo struct pointer into r0 in prep for the syscall
    mov r0, sp
    @ Do the syscall
    swi 0
    @ Move the totalram field into r3, which is where the program needs it
    ldr r3, [sp, #16]
    @ Move the stack pointer back
    add sp, sp, #68
    @ Unclobber r0 and r7
    pop {r0,r7}'''
    instruction_addr = get_patch_location(proj)
    sysinfo_patch = patcherex2.InsertInstructionPatch(instruction_addr, sysinfo_asm)
    proj.patches.append(sysinfo_patch)

    proj.apply_patches()
    proj.binfmt_tool.save_binary("libroscpp-patcherex.so")

apply_nops()
apply_micropatch()
