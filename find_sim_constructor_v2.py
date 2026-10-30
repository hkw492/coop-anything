#!/usr/bin/env python3
"""
Find Simulation vtable using compressed RVA format (RVA << 8 stored in vtable)
And search for constructor pattern.
"""

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe"

def rva_to_file_offset(pe, rva):
    for section in pe.sections:
        sec_start = section.VirtualAddress
        sec_end = section.VirtualAddress + section.Misc_VirtualSize
        if sec_start <= rva < sec_end:
            return (rva - sec_start) + section.PointerToRawData
    return None

def find_section(pe, name):
    for section in pe.sections:
        if section.Name.decode().strip('\x00') == name:
            return section
    return None

def main():
    pe = pefile.PE(EXE_PATH)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    text_sec = find_section(pe, '.text')
    rdata_sec = find_section(pe, '.rdata')
    data_sec = find_section(pe, '.data')

    text_start = image_base + text_sec.VirtualAddress
    text_end = text_start + text_sec.Misc_VirtualSize
    text_data = pe.get_data(text_sec.PointerToRawData, text_sec.Misc_VirtualSize)

    rdata_start = image_base + rdata_sec.VirtualAddress
    rdata_end = rdata_start + rdata_sec.Misc_VirtualSize
    rdata_data = pe.get_data(rdata_sec.PointerToRawData, rdata_sec.Misc_VirtualSize)

    data_start = image_base + data_sec.VirtualAddress
    data_end = data_start + data_sec.Misc_VirtualSize
    data_data = pe.get_data(data_sec.PointerToRawData, data_sec.Misc_VirtualSize)

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    print("=" * 100)
    print("SEARCHING FOR SIMULATION VTABLE IN .RDATA (COMPRESSED RVA FORMAT)")
    print("=" * 100)

    # Look for vtables in .rdata where entries are compressed RVAs (RVA << 8)
    # When decompressed: (entry >> 8) + image_base should point to .text
    vtable_candidates = []

    for i in range(0, len(rdata_data) - 8, 8):
        entry = int.from_bytes(rdata_data[i:i+8], 'little')
        # Check if it's a compressed RVA: (entry >> 8) + image_base in .text
        if entry != 0:
            decompressed_rva = entry >> 8
            ptr = image_base + decompressed_rva
            if text_start <= ptr < text_end:
                # Check consecutive entries
                consecutive = 1
                for j in range(1, 30):
                    if i + j*8 < len(rdata_data):
                        entry2 = int.from_bytes(rdata_data[i+j*8:i+j*8+8], 'little')
                        if entry2 != 0:
                            decompressed_rva2 = entry2 >> 8
                            ptr2 = image_base + decompressed_rva2
                            if text_start <= ptr2 < text_end:
                                consecutive += 1
                            else:
                                break
                        else:
                            break
                if consecutive >= 10:  # At least 10 virtual functions
                    va = rdata_start + i
                    vtable_candidates.append((va, consecutive))

    print(f"Found {len(vtable_candidates)} compressed vtable candidates in .rdata")

    # Filter for ones that look like Simulation vtable (20+ entries for GetSimObject at index 8)
    sim_vtables = [v for v in vtable_candidates if v[1] >= 20]
    print(f"\nVtables with 20+ entries (likely Simulation):")
    for va, count in sim_vtables[:20]:
        rva = va - image_base
        print(f"  VA 0x{va:X} (RVA 0x{rva:X}) - {count} entries")
        # Print first few entries
        offset = (va - rdata_start)
        for j in range(min(count, 15)):
            entry = int.from_bytes(rdata_data[offset+j*8:offset+j*8+8], 'little')
            if entry != 0:
                decompressed_rva = entry >> 8
                ptr = image_base + decompressed_rva
                ptr_rva = decompressed_rva
                print(f"    [{j}] = 0x{entry:016X} -> RVA 0x{ptr_rva:X} (VA 0x{ptr:X})")
            else:
                print(f"    [{j}] = 0x0000000000000000 (null)")

    print("\n" + "=" * 100)
    print("SEARCHING FOR CONSTRUCTOR PATTERN: LEA reg, [vtable] ... MOV [global], reg")
    print("=" * 100)

    # For each candidate Simulation vtable, search for constructor pattern
    for vtable_va, vtable_count in sim_vtables[:10]:
        vtable_rva = vtable_va - image_base
        print(f"\n--- Checking vtable at RVA 0x{vtable_rva:X} (VA 0x{vtable_va:X}) ---")

        # Search for LEA RCX/RAX, [RIP+disp32] pointing to this vtable
        for i in range(len(text_data) - 7):
            # LEA RCX, [RIP+disp32] = 48 8D 0D
            if text_data[i:i+3] == b'\x48\x8d\x0d':
                disp = int.from_bytes(text_data[i+3:i+7], 'little', signed=True)
                instr_va = text_start + i
                target = instr_va + 7 + disp
                if target == vtable_va:
                    print(f"  Found LEA RCX, [vtable] at 0x{instr_va:X} (RVA 0x{instr_va - image_base:X})")
                    # Disassemble next 30 instructions
                    code_bytes = text_data[i:i+300]
                    start_va = instr_va
                    for insn in md.disasm(code_bytes, start_va):
                        bytes_str = " ".join(f"{b:02x}" for b in insn.bytes)
                        print(f"    0x{insn.address:016X}  {bytes_str:<32}  {insn.mnemonic} {insn.op_str}")

                        # Check for MOV [RIP+disp32], RCX
                        if insn.mnemonic == 'mov' and '[rip' in insn.op_str.lower() and ', rcx' in insn.op_str.lower():
                            import re
                            match = re.search(r'\[rip\s*\+\s*0x([0-9a-fA-F]+)\]', insn.op_str)
                            if match:
                                disp2 = int(match.group(1), 16)
                                dest_va = insn.address + insn.size + disp2
                                dest_rva = dest_va - image_base
                                print(f"    >>> GLOBAL STORE RCX: {insn.op_str}")
                                print(f"    >>> Destination: 0x{dest_va:X} (RVA 0x{dest_rva:X})")
                                if data_start <= dest_va < data_end:
                                    print(f"    >>> IN .DATA - CANDIDATE g_pSimulationInstance!")

                        if insn.mnemonic == 'ret':
                            break

            # LEA RAX, [RIP+disp32] = 48 8D 05
            elif text_data[i:i+3] == b'\x48\x8d\x05':
                disp = int.from_bytes(text_data[i+3:i+7], 'little', signed=True)
                instr_va = text_start + i
                target = instr_va + 7 + disp
                if target == vtable_va:
                    print(f"  Found LEA RAX, [vtable] at 0x{instr_va:X} (RVA 0x{instr_va - image_base:X})")
                    code_bytes = text_data[i:i+300]
                    start_va = instr_va
                    for insn in md.disasm(code_bytes, start_va):
                        bytes_str = " ".join(f"{b:02x}" for b in insn.bytes)
                        print(f"    0x{insn.address:016X}  {bytes_str:<32}  {insn.mnemonic} {insn.op_str}")

                        if insn.mnemonic == 'mov' and '[rip' in insn.op_str.lower() and ', rax' in insn.op_str.lower():
                            import re
                            match = re.search(r'\[rip\s*\+\s*0x([0-9a-fA-F]+)\]', insn.op_str)
                            if match:
                                disp2 = int(match.group(1), 16)
                                dest_va = insn.address + insn.size + disp2
                                dest_rva = dest_va - image_base
                                print(f"    >>> GLOBAL STORE RAX: {insn.op_str}")
                                print(f"    >>> Destination: 0x{dest_va:X} (RVA 0x{dest_rva:X})")
                                if data_start <= dest_va < data_end:
                                    print(f"    >>> IN .DATA - CANDIDATE g_pSimulationInstance!")

                        if insn.mnemonic == 'ret':
                            break

if __name__ == "__main__":
    main()