#!/usr/bin/env python3
"""
Disassemble GameState::OnUpdate at RVA 0x00E28610 to find the exact vtable offset
the engine uses to query the player/actors from the Simulation pointer at GameState+0x20.
"""

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe"
ONUPDATE_RVA = 0x00E28610

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

    file_offset = rva_to_file_offset(pe, ONUPDATE_RVA)
    if file_offset is None:
        print(f"ERROR: RVA 0x{ONUPDATE_RVA:X} not found in any section")
        return

    code_bytes = pe.get_data(file_offset, 300)
    va = image_base + ONUPDATE_RVA

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    print(f"Disassembly of GameState::OnUpdate at VA 0x{va:X} (RVA 0x{ONUPDATE_RVA:X}):")
    print("=" * 100)

    count = 0
    simulation_reg = None
    for insn in md.disasm(code_bytes, va):
        bytes_str = " ".join(f"{b:02x}" for b in insn.bytes)
        print(f"0x{insn.address:016X}  {bytes_str:<40}  {insn.mnemonic} {insn.op_str}")

        # Track where [rcx+0x20] (Simulation ptr) is loaded
        if insn.mnemonic == 'mov' and '[rcx' in insn.op_str and '0x20' in insn.op_str:
            # e.g., mov rbx, [rcx+0x20] or mov rax, [rcx+0x20]
            parts = insn.op_str.split(',')
            if len(parts) == 2:
                simulation_reg = parts[0].strip()
                print(f"    ^^^ SIMULATION PTR LOADED INTO {simulation_reg} = [rcx+0x20]")

        # Look for calls using the simulation register
        if simulation_reg and insn.mnemonic == 'call':
            if simulation_reg in insn.op_str:
                print(f"    ^^^ CALL USING SIMULATION REG: {insn.op_str}")

        # Look for vtable calls: mov rax, [rbx]; call [rax+0xXX]
        if insn.mnemonic == 'mov' and '[' in insn.op_str and ']' in insn.op_str:
            if simulation_reg and simulation_reg in insn.op_str:
                # e.g., mov rax, [rbx] - loading vtable pointer
                print(f"    ^^^ VTABLE LOAD: {insn.op_str}")

        if insn.mnemonic == 'call' and '[' in insn.op_str and ']' in insn.op_str:
            # e.g., call [rax+0x30] - virtual call through vtable
            print(f"    ^^^ VTABLE CALL: {insn.op_str}")

        # Look for GetSimObject or similar function calls
        if insn.mnemonic == 'call':
            # Check if it's a direct call to a known function
            print(f"    ^^^ CALL TARGET: {insn.op_str}")

        count += 1
        if count >= 120:
            break

    print("=" * 100)
    print(f"\nTracked simulation register: {simulation_reg}")

if __name__ == "__main__":
    main()