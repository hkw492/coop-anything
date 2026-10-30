#!/usr/bin/env python3
"""
Find UFG::Simulation::m_pInstance (g_pSimulationInstance) via vtable analysis:
Since RTTI strings may be constructed at runtime, search for:
1. Known Simulation vtable entries (from disassembly)
2. Simulation constructor pattern
3. Global pointer stores in .data section
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

    # Find sections
    text_sec = find_section(pe, '.text')
    rdata_sec = find_section(pe, '.rdata')
    data_sec = find_section(pe, '.data')

    if not text_sec or not rdata_sec or not data_sec:
        print("ERROR: Required sections not found")
        return

    text_start = image_base + text_sec.VirtualAddress
    text_end = text_start + text_sec.Misc_VirtualSize
    text_data = pe.get_data(text_sec.PointerToRawData, text_sec.Misc_VirtualSize)

    rdata_start = image_base + rdata_sec.VirtualAddress
    rdata_end = rdata_start + rdata_sec.Misc_VirtualSize
    rdata_data = pe.get_data(rdata_sec.PointerToRawData, rdata_sec.Misc_VirtualSize)

    data_start = image_base + data_sec.VirtualAddress
    data_end = data_start + data_sec.Misc_VirtualSize
    data_data = pe.get_data(data_sec.PointerToRawData, data_sec.Misc_VirtualSize)

    print(f"Image base: 0x{image_base:X}")
    print(f".text: 0x{text_start:X} - 0x{text_end:X}")
    print(f".rdata: 0x{rdata_start:X} - 0x{rdata_end:X}")
    print(f".data: 0x{data_start:X} - 0x{data_end:X}")
    print("=" * 100)

    # Known Simulation vtable entries from COOP_STATE.md:
    # Simulation thunk vtable at RVA 0x01FA0E58 (VA 0x141FA0E58)
    # Simulation GetInstance functions at RVAs 0x152250, 0x152260, 0x152270, 0x152280, 0x152290
    # Simulation vtable entries (compressed format) found at 0x01FA0E58

    print("\n--- Search for Simulation-related strings in .rdata ---")
    search_strings = [
        b"Simulation",
        b"SimObject",
        b"GetSimObject",
        b"m_pInstance",
        b"g_pSimulation",
        b"UFG::Simulation",
    ]

    for s in search_strings:
        offset = 0
        while True:
            idx = rdata_data.find(s, offset)
            if idx == -1:
                break
            va = rdata_start + idx
            rva = va - image_base
            print(f"  Found '{s.decode()}' at VA 0x{va:X} (RVA 0x{rva:X})")
            offset = idx + 1

    print("\n--- Search for Simulation-related strings in .data ---")
    for s in search_strings:
        offset = 0
        while True:
            idx = data_data.find(s, offset)
            if idx == -1:
                break
            va = data_start + idx
            rva = va - image_base
            print(f"  Found '{s.decode()}' at VA 0x{va:X} (RVA 0x{rva:X})")
            offset = idx + 1

    # Search .text for strings
    print("\n--- Search for Simulation-related strings in .text ---")
    for s in search_strings:
        offset = 0
        while True:
            idx = text_data.find(s, offset)
            if idx == -1:
                break
            va = text_start + idx
            rva = va - image_base
            print(f"  Found '{s.decode()}' at VA 0x{va:X} (RVA 0x{rva:X})")
            offset = idx + 1

    # Known vtable at RVA 0x01FA0E58 (from COOP_STATE.md - Simulation Thunk VTable)
    print("\n--- Analyzing known Simulation thunk vtable at RVA 0x01FA0E58 ---")
    known_vtable_rva = 0x01FA0E58
    known_vtable_va = image_base + known_vtable_rva

    # Check if this is in .rdata
    if rdata_start <= known_vtable_va < rdata_end:
        print(f"  VTable at VA 0x{known_vtable_va:X} is in .rdata")
        # Read vtable entries
        offset = (known_vtable_va - rdata_start)
        for i in range(20):
            entry_offset = offset + i * 8
            if entry_offset + 8 <= len(rdata_data):
                entry = int.from_bytes(rdata_data[entry_offset:entry_offset+8], 'little')
                print(f"    [{i}] = 0x{entry:016X} (RVA 0x{entry - image_base:X})")

    # Search for MOV [RIP+disp32], RCX/RAX in .text (global stores)
    # This pattern stores a register value to a global variable
    print("\n--- Search for global pointer stores (MOV [RIP+disp32], RCX/RAX) in .text ---")
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    # Pattern: 48 89 0D disp32 = MOV [RIP+disp32], RCX
    # Pattern: 48 89 05 disp32 = MOV [RIP+disp32], RAX
    global_stores = []
    for i in range(len(text_data) - 6):
        # MOV [RIP+disp32], RCX
        if text_data[i:i+3] == b'\x48\x89\x0d':
            disp = int.from_bytes(text_data[i+3:i+7], 'little', signed=True)
            instr_va = text_start + i
            dest_va = instr_va + 7 + disp
            dest_rva = dest_va - image_base
            # Check if destination is in .data section
            if data_start <= dest_va < data_end:
                global_stores.append((instr_va, dest_va, 'RCX', disp))
        # MOV [RIP+disp32], RAX
        elif text_data[i:i+3] == b'\x48\x89\x05':
            disp = int.from_bytes(text_data[i+3:i+7], 'little', signed=True)
            instr_va = text_start + i
            dest_va = instr_va + 7 + disp
            dest_rva = dest_va - image_base
            if data_start <= dest_va < data_end:
                global_stores.append((instr_va, dest_va, 'RAX', disp))

    print(f"  Found {len(global_stores)} global stores to .data section")

    # Filter for likely Simulation singleton stores
    # Look for stores near Simulation-related code
    sim_related_rvas = [
        0x00152250, 0x00152260, 0x00152270, 0x00152280, 0x00152290,  # SimGetters
        0x00C55270,  # Simulation thunk
        0x00E28480,  # GameState::OnUpdate
        0x00E2C240,  # GameState::OnEnter
        0x004614ED,  # GameState+0x20 init
    ]

    print("\n--- Global stores near Simulation-related code ---")
    for instr_va, dest_va, reg, disp in global_stores:
        instr_rva = instr_va - image_base
        dest_rva = dest_va - image_base

        # Check if instruction is near known Simulation code
        for sim_rva in sim_related_rvas:
            sim_va = image_base + sim_rva
            if abs(instr_va - sim_va) < 0x100:  # Within 256 bytes
                print(f"  0x{instr_va:X} (RVA 0x{instr_rva:X}): MOV [RIP+0x{disp:X}], {reg} -> 0x{dest_va:X} (RVA 0x{dest_rva:X}) NEAR {hex(sim_rva)}")
                # Disassemble context
                code_bytes = pe.get_data(rva_to_file_offset(pe, instr_rva), 64)
                for insn in md.disasm(code_bytes, instr_va):
                    bytes_str = " ".join(f"{b:02x}" for b in insn.bytes)
                    print(f"      0x{insn.address:016X}  {bytes_str:<32}  {insn.mnemonic} {insn.op_str}")
                    if insn.address >= instr_va + 32:
                        break

    # Also search for LEA RCX/RAX, [RIP+disp32] where target is in .data (loading global)
    print("\n--- Search for global pointer loads (LEA RCX/RAX, [RIP+disp32]) from .data ---")
    global_loads = []
    for i in range(len(text_data) - 7):
        # LEA RCX, [RIP+disp32] = 48 8D 0D
        if text_data[i:i+3] == b'\x48\x8d\x0d':
            disp = int.from_bytes(text_data[i+3:i+7], 'little', signed=True)
            instr_va = text_start + i
            src_va = instr_va + 7 + disp
            if data_start <= src_va < data_end:
                global_loads.append((instr_va, src_va, 'RCX', disp))
        # LEA RAX, [RIP+disp32] = 48 8D 05
        elif text_data[i:i+3] == b'\x48\x8d\x05':
            disp = int.from_bytes(text_data[i+3:i+7], 'little', signed=True)
            instr_va = text_start + i
            src_va = instr_va + 7 + disp
            if data_start <= src_va < data_end:
                global_loads.append((instr_va, src_va, 'RAX', disp))

    print(f"  Found {len(global_loads)} global loads from .data section")

    # Look for loads near Simulation getter functions
    print("\n--- Global loads near Simulation getters ---")
    for instr_va, src_va, reg, disp in global_loads:
        instr_rva = instr_va - image_base
        src_rva = src_va - image_base

        for sim_rva in sim_related_rvas:
            sim_va = image_base + sim_rva
            if abs(instr_va - sim_va) < 0x100:
                print(f"  0x{instr_va:X} (RVA 0x{instr_rva:X}): LEA {reg}, [RIP+0x{disp:X}] -> 0x{src_va:X} (RVA 0x{src_rva:X}) NEAR {hex(sim_rva)}")
                # Disassemble context
                code_bytes = pe.get_data(rva_to_file_offset(pe, instr_rva), 64)
                for insn in md.disasm(code_bytes, instr_va):
                    bytes_str = " ".join(f"{b:02x}" for b in insn.bytes)
                    print(f"      0x{insn.address:016X}  {bytes_str:<32}  {insn.mnemonic} {insn.op_str}")
                    if insn.address >= instr_va + 32:
                        break

    # Now search for constructor pattern: LEA RCX/RAX, [vtable] followed by MOV [global], RCX/RAX
    print("\n--- Search for constructor pattern: LEA reg, [vtable] ... MOV [global], reg ---")
    known_vtables = [
        0x01FA0E58,  # Simulation thunk vtable
        0x01784BD0,  # InGame GameState vtable
    ]

    for vtable_rva in known_vtables:
        vtable_va = image_base + vtable_rva
        print(f"\n  Checking vtable at RVA 0x{vtable_rva:X} (VA 0x{vtable_va:X})")

        # Find LEA to this vtable
        for i in range(len(text_data) - 7):
            found = False
            reg = None
            # LEA RCX, [RIP+disp32]
            if text_data[i:i+3] == b'\x48\x8d\x0d':
                disp = int.from_bytes(text_data[i+3:i+7], 'little', signed=True)
                instr_va = text_start + i
                target = instr_va + 7 + disp
                if target == vtable_va:
                    found = True
                    reg = 'RCX'
            # LEA RAX, [RIP+disp32]
            elif text_data[i:i+3] == b'\x48\x8d\x05':
                disp = int.from_bytes(text_data[i+3:i+7], 'little', signed=True)
                instr_va = text_start + i
                target = instr_va + 7 + disp
                if target == vtable_va:
                    found = True
                    reg = 'RAX'

            if found:
                print(f"    Found LEA {reg}, [vtable] at 0x{instr_va:X} (RVA 0x{instr_va - image_base:X})")
                # Disassemble next 30 instructions looking for MOV [global], reg
                code_bytes = text_data[i:i+200]
                start_va = text_start + i
                for insn in md.disasm(code_bytes, start_va):
                    bytes_str = " ".join(f"{b:02x}" for b in insn.bytes)
                    print(f"      0x{insn.address:016X}  {bytes_str:<32}  {insn.mnemonic} {insn.op_str}")

                    # Check for MOV [RIP+disp32], reg
                    if insn.mnemonic == 'mov' and '[' in insn.op_str and 'rip' in insn.op_str.lower():
                        if f', {reg.lower()}' in insn.op_str.lower():
                            import re
                            match = re.search(r'\[rip\s*\+\s*0x([0-9a-fA-F]+)\]', insn.op_str)
                            if match:
                                disp2 = int(match.group(1), 16)
                                dest_va = insn.address + insn.size + disp2
                                dest_rva = dest_va - image_base
                                print(f"      >>> GLOBAL STORE: {insn.op_str}")
                                print(f"      >>> Destination VA: 0x{dest_va:X} (RVA 0x{dest_rva:X})")
                                if data_start <= dest_va < data_end:
                                    print(f"      >>> IN .DATA SECTION - Candidate g_pSimulationInstance!")

                    if insn.mnemonic == 'ret':
                        break

if __name__ == "__main__":
    main()