import patcherex2

# Note: this script requires patcherex2 which can be installed via PyPI: pip3 install patcherex2

# If you experience an error regarding a missing lld linker, add the following repo to your packages:
# https://apt.llvm.org/
# Then run "sudo apt-get install lld-15"

def apply_badpatch():
    validateSerialized_c = '''
void validateSerialized(char *serialized) {
    for (int idx = 0, cnt = 0; serialized[idx]; idx++) {
        if (serialized[idx] == ';') cnt++;
        if (cnt > 2) {
            puts("bad serialization!");
            exit(1);
        }
    }
}'''
    validate_serialized_branchless_c = '''
void validateSerialized(char *serialized) {
    int cnt = 0;
    for (int idx = 0; serialized[idx]; idx++) {
        cnt += (serialized[idx] == ';');
    }
    if (cnt > 2) {
        puts("bad serialization!");
        exit(1);
    }
}'''

    proj = patcherex2.Patcherex("injectionAttack")

    call_addr = proj.binary_analyzer.get_function('receiver')['addr'] + 0x4

    call_asm = '''
    push rdi
    call {validateSerialized}
    pop rdi
    '''

    validate_serialized_patch = patcherex2.InsertFunctionPatch("validateSerialized", validate_serialized_branchless_c)
    call_patch = patcherex2.InsertInstructionPatch(call_addr, call_asm)

    proj.patches.append(validate_serialized_patch)
    proj.patches.append(call_patch)

    proj.apply_patches()

    proj.binfmt_tool.save_binary("injectionAttack-badPatch-patcherex")

def apply_goodpatch():
    validateCommand_c = '''
void validateCommand(char *command) {
    for (int idx = 0; command[idx]; idx++) {
        if (command[idx] == ';') {
            puts("bad command!");
            exit(1);
        }
    }
}
'''

    proj = patcherex2.Patcherex("injectionAttack")

    call_addr = proj.binary_analyzer.get_function('main')['addr'] + 0x30
    call_asm = '''
    mov rdi,rax
    call {validateCommand}
    '''

    validate_command_patch = patcherex2.InsertFunctionPatch("validateCommand", validateCommand_c)
    call_patch = patcherex2.InsertInstructionPatch(call_addr, call_asm)

    proj.patches.append(validate_command_patch)
    proj.patches.append(call_patch)

    proj.apply_patches()

    proj.binfmt_tool.save_binary("injectionAttack-goodPatch-patcherex")

def apply_patches():
    apply_goodpatch()
    apply_badpatch()

if __name__ == '__main__':
    apply_patches()