import os
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

# change working directory to the script's directory
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# initialize assembler and disassembler
ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

def assemble(instructions: list[str]) -> str:
    """assembles a list of arm64 instructions to a hex string."""
    hex_output = ""
    for instruction in instructions:
        encoded, _ = ks.asm(instruction)
        hex_output += bytes(encoded).hex()
    return hex_output

def disassemble(hex_data: str) -> list[str]:
    """disassembles hex string to arm64 assembly instructions."""
    disassembled = []
    for insn in cs.disasm(bytes.fromhex(hex_data), 0x0):
        disassembled.append(f"{insn.mnemonic}\t{insn.op_str}")
    return disassembled

def generate_jump(addr: int, target: int, count: int) -> str:
    """generates a jump to the target address."""
    instructions = [
        "mov x11, x30",
        f"bl #{target - addr - 4}",
    ]
    return assemble(instructions)

# read the original binary content
with open("bin/gdbinary", "rb") as f:
    binary_content = f.read()

def read_from_binary(address: int, length: int) -> str:
    """reads a section from the binary file."""
    return binary_content[address: address + length // 2].hex()

def apply_patch(index: int, new_data: str):
    """applies a patch to the binary content."""
    global binary_content
    new_bytes = bytes.fromhex(new_data)
    binary_content = binary_content[:index] + new_bytes + binary_content[index + len(new_bytes):]

hook_address = 0x62AD34
code_output = "#include <kamp.h++>\n"
code_output += "namespace origs {\n"

condition_code = ""
hook_code = ""

hook_counter = 0

def create_hook_function(hook_name: str, address: int) -> str:
    """generates hook function for the given address."""
    global hook_counter
    global code_output
    global condition_code
    global hook_code

    hook_counter += 1
    sanitized_name = hook_name.replace("::", "_")
    jump_code = generate_jump(address, hook_address, hook_counter)

    code_output += f"long _{sanitized_name};\n"
    code_output += f"__attribute__((naked)) void {sanitized_name}() {{\n"
    code_output += "\tasm volatile(\n"

    original_instructions = disassemble(read_from_binary(address, len(jump_code)))

    for inst in original_instructions:
        code_output += f'\t\t"{inst}\\n"\n'

    code_output += '\t\t"br %[ptr]\\n"\n'
    code_output += f'\t\t: : [ptr]"r"(_{sanitized_name})\n'
    code_output += "\t);\n"
    code_output += "}\n"

    condition_code += f'\tif (sig == "{hook_name}") return kamp::internal::base() + {address};\n'
    hook_code += f'\torigs::_{sanitized_name} = kamp::internal::resolve("{hook_name}") + 8;\n'
    hook_code += f'\tm->insert_or_assign((void *)kamp::internal::resolve("{hook_name}"), (void *)&origs::{sanitized_name});\n'

    apply_patch(address, jump_code)

# apply patches for hook addresses
apply_patch(
    hook_address,
    assemble([
        "ldr x9, =0x3",
        "lsl x9, x9, #32",
        "ldr x10, =0x20000000",
        "orr x9, x9, x10",
        "ldr x9, [x9]",
        "br x9",
    ])
)

# create hooks for various functions
create_hook_function("MenuLayer::init", 0x27604C)
create_hook_function("LoadingLayer::init", 0x1DFA60)
create_hook_function("GameManager::isIconUnlocked", 0x3235D4)
create_hook_function("GameManager::isColorUnlocked", 0x3239A4)
create_hook_function("EditLevelLayer::init", 0xEA62C)
create_hook_function("LevelBrowserLayer::init", 0x41D238)

# finalize generated c++ code
code_output += "}\n\n"
code_output += "uintptr_t kamp::internal::resolve(std::string sig) {\n"
code_output += condition_code
code_output += "\treturn -1;\n"
code_output += "}\n\n"
code_output += "void kamp::internal::load_origs(std::map<void*, void*>* m) {\n"
code_output += hook_code
code_output += "}\n"

# write the generated c++ code to file
with open("src/generated.cc", "w") as f:
    f.write(code_output)

# write the patched binary content back to file
with open("bin/GeometryJump", "wb") as f:
    f.write(binary_content)