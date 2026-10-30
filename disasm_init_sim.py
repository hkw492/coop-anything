#!/usr/bin/env python3
"""
Disassemble the function at 0x004614ED that initializes GameState+0x20 with Simulation pointer
"""

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe"
INIT_RVA = 0x004614ED

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

    file_offset = rva_to_file_offset(pe, INIT_RVA)
    if file_offset is None:
        print(f"ERROR: RVA 0x{INIT_RVA:X} not found")
        return

    # Go back a bit to find function entry
    start_rva = INIT_RVA - 0x30
    file_offset = rva_to_file_offset(pe, start_rva)
    if file_offset is None:
        print(f"ERROR: RVA 0x{start_rva:X} not found")
        return

    code_bytes = pe.get_data(file_offset, 200)
    va = image_base + start_rva

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    print(f"Disassembly from VA 0x{va:X} (RVA 0x{start_rva:X}) - Init GameState+0x20:")
    print("=" * 100)

    count = 0
    for insn in md.disasm(code_bytes, va):
        bytes_str = " ".join(f"{b:02x}" for b in insn.bytes)
        marker = " >>> INIT POINT (0x4614ED) <<<" if insn.address == image_base + INIT_RVA else ""
        print(f"0x{insn.address:016X}  {bytes_str:<32}  {insn.mnemonic} {insn.op_str}{marker}")

        # Look for Simulation thunk call
        if insn.mnemonic == 'call':
            print(f"    ^^^ CALL: {insn.op_str}")

        # Look for [rcx+0x20] write (storing Simulation ptr)
        if insn.mnemonic == 'mov' and '[rcx' in insn.op_str and '0x20' in insn.op_str:
            print(f"    ^^^ GAMESTATE+0x20 WRITE: {insn.op_str}")

        count += 1
        if count >= 100:
            break

    print("=" * 100)

if __name__ == "__main__":
    main()