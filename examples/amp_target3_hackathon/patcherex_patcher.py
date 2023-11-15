import patcherex
from patcherex.backends.detourbackend import DetourBackend
from patcherex.backends.reassembler_backend import ReassemblerBackend
from patcherex.patches import *

backend = DetourBackend("libroscpp.so")

# Reassembler backend doesn't seem to work with ARM
#backend = ReassemblerBackend("libroscpp.so")

patches = []

sysinfo_asm = '''
push {{r0,r7,lr}}
sub sp, sp, #68
mov r7, #116
mov r0, sp
swi 0
ldr r3, [sp, #16]
add sp, sp, #68
pop {{r0,r7,pc}}'''

patches.append(AddCodePatch(sysinfo_asm, name="sysinfo_function"))

onMessageLength_mangled = "_ZN3ros22TransportPublisherLink15onMessageLengthERKN5boost10shared_ptrINS_10ConnectionEEERKNS1_12shared_arrayIhEEjb"
onMessageLengthStart = backend.project.loader.find_symbol(onMessageLength_mangled).rebased_addr
offset = 0xf8
instruction_addr = onMessageLengthStart + offset
num_instr = 2

inline_asm = '''
nop
bl {sysinfo_function}'''

patches.append(InlinePatch(instruction_addr, inline_asm, num_instr=2))

# now we ask to the backend to inject all our patches
backend.apply_patches(patches)
# and then we save the file
backend.save("libroscpp_patcherex_output.so")