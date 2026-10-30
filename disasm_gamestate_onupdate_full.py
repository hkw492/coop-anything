#!/usr/bin/env python3
"""
Disassemble GameState::OnUpdate at RVA 0x00E28480 (first 60 instructions)
Using pefile + capstone to trace how [rcx + 0x20] is used and identify
the exact function/virtual method call the game makes on that pointer.
"""

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe"
FUNC_RVA = 0x00E28480  # GameState::OnUpdate entry point

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
        print(f"ERROR: RVA 0x{FUNC_RVA:X} not found in any section")
        return

    # Read enough bytes for ~60 instructions (conservative estimate: 4 bytes avg = 240 bytes)
    code_bytes = pe.get_data(file_offset, 400)
    va = image_base + FUNC_RVA

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    print(f"Disassembly of GameState::OnUpdate at VA 0x{va:X} (RVA 0x{FUNC_RVA:X}):")
    print("=" * 120)
    print(f"{'Address':<20} {'Bytes':<32} {'Instruction':<40} {'Notes'}")
    print("-" * 120)

    count = 0
    for insn in md.disasm(code_bytes, va):
        bytes_str = " ".join(f"{b:02x}" for b in insn.bytes)

        # Analyze for key patterns
        notes = []
        op_str = insn.op_str

        # Look for [rcx + 0x20] or [rdi + 0x20] access (Simulation pointer usage)
        if '[rcx + 0x20]' in op_str or '[rdi + 0x20]' in op_str:
            notes.append(">>> SIMULATION_PTR_ACCESS (+0x20)")
        if '[rcx + 0x98]' in op_str or '[rdi + 0x98]' in op_str:
            notes.append(">>> GAMESTATE+0x98_ACCESS")
        if '[rcx + 0x30]' in op_str or '[rdi + 0x30]' in op_str:
            notes.append(">>> GAMESTATE+0x30_ACCESS")
        if '[rcx + 0x38]' in op_str or '[rdi + 0x38]' in op_str:
            notes.append(">>> GAMESTATE+0x38_ACCESS")

        # Look for calls
        if insn.mnemonic == 'call':
            notes.append(f">>> CALL: {insn.op_str}")

        # Look for virtual calls (call [reg])
        if insn.mnemonic == 'call' and '[' in insn.op_str:
            notes.append(f">>> VIRTUAL_CALL: {insn.op_str}")

        # Look for returns
        if insn.mnemonic == 'ret':
            notes.append(">>> RETURN")

        # Look for RIP-relative loads (vtable pointers)
        if insn.mnemonic in ['mov', 'lea'] and 'rip' in op_str:
            notes.append(f">>> RIP_RELATIVE: {op_str}")

        note_str = " | ".join(notes) if notes else ""
        print(f"0x{insn.address:016X}  {bytes_str:<32}  {insn.mnemonic} {insn.op_str:<35}  {note_str}")

        count += 1
        if count >= 60:
            break

        if insn.mnemonic == 'ret':
            break

    print("=" * 120)

if __name__ == "__main__":
    main()