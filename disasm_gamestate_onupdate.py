#!/usr/bin/env python3
"""
Disassemble GameState::OnUpdate at RVA 0x00E28610 (the real InGame_OnUpdate)
to understand how it uses the Simulation pointer from GameState+0x20.
Uses capstone for disassembly directly on the PE file.
"""

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import sys
import os

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe"
GAMESTATE_ONUPDATE_RVA = 0x00E28610
NUM_INSTRUCTIONS = 60

def rva_to_file_offset(pe, rva):
    """Convert RVA to file offset."""
    for section in pe.sections:
        sec_start = section.VirtualAddress
        sec_end = section.VirtualAddress + section.Misc_VirtualSize
        if sec_start <= rva < sec_end:
            return (rva - sec_start) + section.PointerToRawData
    return None

def main():
    print(f"Loading {EXE_PATH}...")
    pe = pefile.PE(EXE_PATH)

    # Get module base (preferred image base)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    print(f"Image Base: 0x{image_base:X}")

    # Convert RVA to file offset
    file_offset = rva_to_file_offset(pe, GAMESTATE_ONUPDATE_RVA)
    if file_offset is None:
        print(f"ERROR: RVA 0x{GAMESTATE_ONUPDATE_RVA:X} not found in any section")
        return

    print(f"RVA 0x{GAMESTATE_ONUPDATE_RVA:X} -> File Offset 0x{file_offset:X}")

    # Read code bytes
    pe.__data__ = pe.__data__  # ensure data is loaded
    code_bytes = pe.get_data(file_offset, 256)  # Read enough bytes for ~60 instructions

    # Disassemble with capstone
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    md.syntax = 0  # Intel syntax

    # Virtual address for display
    va = image_base + GAMESTATE_ONUPDATE_RVA

    print(f"\nDisassembly at VA 0x{va:X} (RVA 0x{GAMESTATE_ONUPDATE_RVA:X}):")
    print("=" * 80)

    count = 0
    for insn in md.disasm(code_bytes, va):
        # Print instruction with bytes
        bytes_str = " ".join(f"{b:02x}" for b in insn.bytes)
        print(f"0x{insn.address:016X}  {bytes_str:<32}  {insn.mnemonic} {insn.op_str}")

        # Highlight interesting instructions
        if insn.mnemonic in ['call', 'jmp', 'mov'] and ('rax' in insn.op_str or 'rbx' in insn.op_str or 'rcx' in insn.op_str or '[r' in insn.op_str):
            print(f"    ^^^ INTERESTING: {insn.mnemonic} {insn.op_str}")

        count += 1
        if count >= NUM_INSTRUCTIONS:
            break

    print("=" * 80)
    print(f"Total instructions shown: {count}")

if __name__ == "__main__":
    main()