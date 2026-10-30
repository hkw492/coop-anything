#!/usr/bin/env python3
"""
Disassemble GameState::OnUpdate at RVA 0x00E28610 - look at function prologue
"""

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe"
GAMESTATE_ONUPDATE_RVA = 0x00E28610

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

    # Disassemble from 32 bytes BEFORE the RVA to catch prologue
    start_rva = GAMESTATE_ONUPDATE_RVA - 0x20
    file_offset = rva_to_file_offset(pe, start_rva)
    if file_offset is None:
        print(f"ERROR: RVA 0x{start_rva:X} not found")
        return

    code_bytes = pe.get_data(file_offset, 384)
    va = image_base + start_rva

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    print(f"Disassembly from VA 0x{va:X} (RVA 0x{start_rva:X}) - includes prologue:")
    print("=" * 80)

    count = 0
    for insn in md.disasm(code_bytes, va):
        bytes_str = " ".join(f"{b:02x}" for b in insn.bytes)
        marker = " >>> ENTRY POINT <<<" if insn.address == image_base + GAMESTATE_ONUPDATE_RVA else ""
        print(f"0x{insn.address:016X}  {bytes_str:<32}  {insn.mnemonic} {insn.op_str}{marker}")

        # Highlight interesting instructions
        if insn.mnemonic in ['call', 'jmp', 'mov', 'lea'] and ('rcx' in insn.op_str or 'rbx' in insn.op_str or 'rdi' in insn.op_str or '[r' in insn.op_str):
            if '0x20' in insn.op_str or '20h' in insn.op_str or '0x20]' in insn.op_str:
                print(f"    ^^^ INTERESTING (offset 0x20): {insn.mnemonic} {insn.op_str}")

        count += 1
        if count >= 80:
            break

    print("=" * 80)

if __name__ == "__main__":
    main()