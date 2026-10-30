#!/usr/bin/env python3
"""
Disassemble around the CALL to Simulation thunk to find GameState+0x20 store
"""

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe"

CALL_RVAS = [0x0009828E, 0x0009832A, 0x0009A886, 0x0009A88F, 0x0009A9B6, 0x0009A9C3, 0x0009A9D1]

def rva_to_file_offset(pe, rva):
    for section in pe.sections:
        sec_start = section.VirtualAddress
        sec_end = section.VirtualAddress + section.Misc_VirtualSize
        if sec_start <= rva < sec_end:
            return (rva - sec_start) + section.PointerToRawData
    return None

def disasm_around(pe, image_base, call_rva, name):
    # Go back 40 bytes before call
    start_rva = call_rva - 0x30
    file_offset = rva_to_file_offset(pe, start_rva)
    if file_offset is None:
        print(f"ERROR: RVA 0x{start_rva:X} not found")
        return

    code_bytes = pe.get_data(file_offset, 120)
    va = image_base + start_rva

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    print(f"\n{'='*60}")
    print(f"Disassembly around {name} at VA 0x{image_base + call_rva:X} (RVA 0x{call_rva:X}):")
    print(f"{'='*60}")

    count = 0
    for insn in md.disasm(code_bytes, va):
        bytes_str = " ".join(f"{b:02x}" for b in insn.bytes)
        marker = " >>> CALL <<<" if insn.address == image_base + call_rva else ""
        print(f"0x{insn.address:016X}  {bytes_str:<32}  {insn.mnemonic} {insn.op_str}{marker}")

        # Look for store to [rcx+0x20] or [rdi+0x20] etc.
        if insn.mnemonic == 'mov' and '[' in insn.op_str and '0x20' in insn.op_str:
            print(f"    ^^^ OFFSET 0x20 STORE: {insn.op_str}")

        count += 1
        if count >= 60:
            break

def main():
    pe = pefile.PE(EXE_PATH)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    for rva in CALL_RVAS:
        disasm_around(pe, image_base, rva, f"CALL at RVA 0x{rva:X}")

if __name__ == "__main__":
    main()