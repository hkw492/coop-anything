#!/usr/bin/env python3
"""
Disassemble the function at 0xC5C930 called by Simulation thunk
"""

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe"
FUNC_RVA = 0x00C5C930

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

    file_offset = rva_to_file_offset(pe, FUNC_RVA)
    if file_offset is None:
        print(f"ERROR: RVA 0x{FUNC_RVA:X} not found")
        return

    code_bytes = pe.get_data(file_offset, 200)
    va = image_base + FUNC_RVA

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    print(f"Disassembly of function at VA 0x{va:X} (RVA 0x{FUNC_RVA:X}):")
    print("=" * 100)

    count = 0
    for insn in md.disasm(code_bytes, va):
        bytes_str = " ".join(f"{b:02x}" for b in insn.bytes)
        print(f"0x{insn.address:016X}  {bytes_str:<32}  {insn.mnemonic} {insn.op_str}")

        # Look for vtable references
        if insn.mnemonic in ['mov', 'lea'] and '[' in insn.op_str and 'rip' in insn.op_str:
            print(f"    ^^^ RIP-RELATIVE: {insn.op_str}")

        if insn.mnemonic == 'call':
            print(f"    ^^^ CALL: {insn.op_str}")

        if insn.mnemonic == 'ret':
            print(f"    ^^^ RETURN")
            break

        count += 1
        if count >= 80:
            break

    print("=" * 100)

if __name__ == "__main__":
    main()