#!/usr/bin/env python3
"""
Disassemble the call targets from GameState::OnUpdate to find how the engine
uses the Simulation pointer to get players/actors.
"""

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe"

TARGETS = [
    (0x00C57960, "Call target 1 from OnUpdate"),
    (0x00C57820, "Call target 2 from OnUpdate"),
    (0x00C55270, "Simulation thunk (first virtual)"),
]

def rva_to_file_offset(pe, rva):
    for section in pe.sections:
        sec_start = section.VirtualAddress
        sec_end = section.VirtualAddress + section.Misc_VirtualSize
        if sec_start <= rva < sec_end:
            return (rva - sec_start) + section.PointerToRawData
    return None

def disasm_at(pe, image_base, rva, name, max_insns=80):
    file_offset = rva_to_file_offset(pe, rva)
    if file_offset is None:
        print(f"ERROR: RVA 0x{rva:X} not found")
        return

    code_bytes = pe.get_data(file_offset, max_insns * 6)
    va = image_base + rva

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    print(f"\n{'='*60}")
    print(f"Disassembly of {name} at VA 0x{va:X} (RVA 0x{rva:X}):")
    print(f"{'='*60}")

    count = 0
    for insn in md.disasm(code_bytes, va):
        bytes_str = " ".join(f"{b:02x}" for b in insn.bytes)
        print(f"0x{insn.address:016X}  {bytes_str:<32}  {insn.mnemonic} {insn.op_str}")

        # Look for qSymbol usage (Player = 0x9FB57F53, WeiShen = 0x9AF96AFB)
        if '9FB57F53' in bytes_str or '9AF96AFB' in bytes_str:
            print(f"    ^^^ qSymbol HASH FOUND: {bytes_str}")

        # Look for vtable calls
        if insn.mnemonic == 'call' and '[' in insn.op_str and ']' in insn.op_str:
            print(f"    ^^^ VTABLE CALL: {insn.op_str}")

        if insn.mnemonic == 'mov' and '[' in insn.op_str and ']' in insn.op_str and '+' in insn.op_str:
            if '0x20' in insn.op_str or '20h' in insn.op_str:
                print(f"    ^^^ OFFSET 0x20 ACCESS: {insn.op_str}")

        # Look for GetSimObject-like patterns
        if insn.mnemonic == 'call':
            print(f"    ^^^ CALL: {insn.op_str}")

        count += 1
        if count >= max_insns:
            break

def main():
    pe = pefile.PE(EXE_PATH)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    for rva, name in TARGETS:
        disasm_at(pe, image_base, rva, name, max_insns=80)

if __name__ == "__main__":
    main()