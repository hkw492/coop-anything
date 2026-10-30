#!/usr/bin/env python3
"""
Disassemble BEFORE the loop start to find function entry/prologue
"""

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe"
LOOP_START_RVA = 0x00E28510

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

    # Go back 200 bytes from loop start to find function entry
    start_rva = LOOP_START_RVA - 0xC8
    file_offset = rva_to_file_offset(pe, start_rva)
    if file_offset is None:
        print(f"ERROR: RVA 0x{start_rva:X} not found")
        return

    code_bytes = pe.get_data(file_offset, 700)
    va = image_base + start_rva

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    print(f"Disassembly from VA 0x{va:X} (RVA 0x{start_rva:X}) - looking for function entry:")
    print("=" * 80)

    count = 0
    for insn in md.disasm(code_bytes, va):
        bytes_str = " ".join(f"{b:02x}" for b in insn.bytes)
        marker = " >>> LOOP START <<<" if insn.address == image_base + LOOP_START_RVA else ""
        marker2 = " >>> DOCUMENTED ENTRY 0xE28610 <<<" if insn.address == image_base + 0x00E28610 else ""
        print(f"0x{insn.address:016X}  {bytes_str:<32}  {insn.mnemonic} {insn.op_str}{marker}{marker2}")

        # Look for function prologue patterns
        if insn.mnemonic in ['push', 'mov'] and ('rbp' in insn.op_str or 'rsp' in insn.op_str):
            print(f"    ^^^ PROLOGUE CANDIDATE: {insn.mnemonic} {insn.op_str}")
        if insn.mnemonic in ['mov', 'lea'] and 'rcx' in insn.op_str and 'rdi' in insn.op_str:
            print(f"    ^^^ RCX->RDI MOVE (this pointer): {insn.mnemonic} {insn.op_str}")
        if insn.mnemonic in ['mov'] and ('[rcx' in insn.op_str or '[rdi' in insn.op_str) and '0x20' in insn.op_str:
            print(f"    ^^^ GAMESTATE+0x20 ACCESS: {insn.mnemonic} {insn.op_str}")

        count += 1
        if count >= 200:
            break

    print("=" * 80)

if __name__ == "__main__":
    main()