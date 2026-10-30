#!/usr/bin/env python3
"""
Disassemble GameState::OnUpdate from the ACTUAL FUNCTION ENTRY at RVA 0x00E28480
to find how it loads and uses the Simulation pointer from GameState+0x20.
"""

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe"
ENTRY_RVA = 0x00E28480

def rva_to_file_offset(pe, rva):
    for section in pe.sections:
        sec_start = section.VirtualAddress
        sec_end = section.VirtualAddress + section.Misc_VirtualSize
        if sec_start <= rva < sec_end:
            return (rva - sec_start) + section.PointerToRawData
    return None

def main():
    pe = pefile.PE(EXE_PATH)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    file_offset = rva_to_file_offset(pe, ENTRY_RVA)
    if file_offset is None:
        print(f"ERROR: RVA 0x{ENTRY_RVA:X} not found in any section")
        return

    code_bytes = pe.get_data(file_offset, 400)
    va = image_base + ENTRY_RVA

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    print(f"Disassembly of GameState::OnUpdate ENTRY at VA 0x{va:X} (RVA 0x{ENTRY_RVA:X}):")
    print("=" * 100)

    count = 0
    for insn in md.disasm(code_bytes, va):
        bytes_str = " ".join(f"{b:02x}" for b in insn.bytes)
        marker = " >>> LOOP START (0xE28510) <<<" if insn.address == image_base + 0xE28510 else ""
        marker2 = " >>> DOCUMENTED ENTRY (0xE28610) <<<" if insn.address == image_base + 0xE28610 else ""
        print(f"0x{insn.address:016X}  {bytes_str:<40}  {insn.mnemonic} {insn.op_str}{marker}{marker2}")

        # Track where [rcx+0x20] (Simulation ptr) is loaded - rcx = GameState (this)
        if insn.mnemonic == 'mov' and ('[rcx' in insn.op_str or '[rdi' in insn.op_str or '[rbx' in insn.op_str) and '0x20' in insn.op_str:
            print(f"    ^^^ SIMULATION PTR ACCESS (offset 0x20): {insn.op_str}")

        # Look for vtable calls: mov rax, [reg]; call [rax+0xXX]
        if insn.mnemonic == 'mov' and '[' in insn.op_str and ']' in insn.op_str and '+' in insn.op_str:
            print(f"    ^^^ VTABLE LOAD: {insn.op_str}")

        if insn.mnemonic == 'call' and '[' in insn.op_str and ']' in insn.op_str:
            print(f"    ^^^ VTABLE CALL: {insn.op_str}")

        # Any call instruction
        if insn.mnemonic == 'call':
            print(f"    ^^^ CALL: {insn.op_str}")

        count += 1
        if count >= 150:
            break

    print("=" * 100)

if __name__ == "__main__":
    main()