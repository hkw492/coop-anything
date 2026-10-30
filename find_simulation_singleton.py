#!/usr/bin/env python3
"""
Find UFG::Simulation::m_pInstance (g_pSimulationInstance) via RTTI analysis:
1. Search .rdata for ASCII RTTI type descriptor: ".?AVSimulation@UFG@@"
2. Find CompleteObjectLocator pointing to that TypeDescriptor
3. Find primary Simulation vtable in .rdata pointing to that CompleteObjectLocator
4. Search .text for constructor instruction: 'lea rax/rcx, [Simulation_vtable_RVA]'
5. Disassemble following 15 instructions to find 'mov [rip + disp32], rcx' storing to global
6. Calculate RVA of that destination global variable in .data
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

    # Step 1: Search .rdata for RTTI type descriptor ".?AVSimulation@UFG@@"
    rtti_typename = b".?AVSimulation@UFG@@"
    print(f"\n--- Step 1: Search for RTTI type descriptor '{rtti_typename.decode()}' in .rdata ---")

    rtti_type_desc_vas = []
    offset = 0
    while True:
        idx = rdata_data.find(rtti_typename, offset)
        if idx == -1:
            break
        va = rdata_start + idx
        rva = va - image_base
        rtti_type_desc_vas.append(va)
        print(f"  Found at VA 0x{va:X} (RVA 0x{rva:X})")
        offset = idx + 1

    if not rtti_type_desc_vas:
        print("  NOT FOUND - trying alternative mangled names...")
        # Try other common mangled forms
        for alt in [b"Simulation@UFG@@", b"?AVSimulation@UFG@@", b"UFG@@Simulation"]:
            offset = 0
            while True:
                idx = rdata_data.find(alt, offset)
                if idx == -1:
                    break
                va = rdata_start + idx
                rva = va - image_base
                print(f"  Alt found at VA 0x{va:X} (RVA 0x{rva:X})")
                offset = idx + 1

    # Step 2: Find CompleteObjectLocator pointing to TypeDescriptor
    # COL structure (MSVC x64):
    # +0x00: pTypeDescriptor (ptr to type_info)
    # +0x08: offset (usually 0)
    # +0x10: cdOffset (usually -1)
    # +0x18: pClassDescriptor
    # +0x20: pSelf (ptr to this COL)

    print("\n--- Step 2: Find CompleteObjectLocator for Simulation ---")
    col_vas = []
    for type_desc_va in rtti_type_desc_vas:
        target_bytes = type_desc_va.to_bytes(8, 'little')
        # Search .rdata for pointer to TypeDescriptor
        for i in range(0, len(rdata_data) - 8, 8):
            if rdata_data[i:i+8] == target_bytes:
                col_va = rdata_start + i
                col_rva = col_va - image_base
                col_vas.append(col_va)
                print(f"  Found COL at VA 0x{col_va:X} (RVA 0x{col_rva:X}) pointing to TypeDescriptor 0x{type_desc_va:X}")

    # Step 3: Find vtable pointing to COL
    # Vtable layout (MSVC x64):
    # [-8] = offset_to_top (usually 0)
    # [-16] = RTTI CompleteObjectLocator pointer
    # [0] = first virtual function
    # So vtable[-2] (index -2) = COL pointer

    print("\n--- Step 3: Find Simulation vtable pointing to COL ---")
    vtable_vas = []
    for col_va in col_vas:
        target_bytes = col_va.to_bytes(8, 'little')
        # Search .rdata for pointer to COL (at vtable[-2] position)
        for i in range(16, len(rdata_data) - 8, 8):  # skip first 16 bytes (offset_to_top + RTTI)
            if rdata_data[i:i+8] == target_bytes:
                vtable_va = rdata_start + i - 16  # vtable base is 16 bytes before RTTI pointer
                vtable_rva = vtable_va - image_base
                vtable_vas.append(vtable_va)
                print(f"  Found vtable at VA 0x{vtable_va:X} (RVA 0x{vtable_rva:X}) -> COL at 0x{col_va:X}")

    if not vtable_vas:
        # Try searching for vtable that has COL pointer at offset 8 (vtable[1] = RTTI ptr in some layouts)
        print("  Trying alternative vtable layout (RTTI at vtable[1])...")
        for col_va in col_vas:
            target_bytes = col_va.to_bytes(8, 'little')
            for i in range(8, len(rdata_data) - 8, 8):
                if rdata_data[i:i+8] == target_bytes:
                    vtable_va = rdata_start + i - 8  # vtable base is 8 bytes before RTTI pointer
                    vtable_rva = vtable_va - image_base
                    vtable_vas.append(vtable_va)
                    print(f"  Found vtable (alt layout) at VA 0x{vtable_va:X} (RVA 0x{vtable_rva:X}) -> COL at 0x{col_va:X}")

    # Step 4: Search .text for constructor LEA to vtable
    print("\n--- Step 4: Search .text for constructor LEA to Simulation vtable ---")
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    for vtable_va in vtable_vas:
        vtable_rva = vtable_va - image_base
        print(f"\n  Analyzing vtable at RVA 0x{vtable_rva:X} (VA 0x{vtable_va:X})")

        # Search for LEA instructions loading this vtable address
        # LEA RAX, [RIP + disp32] -> 48 8D 05 disp32
        # LEA RCX, [RIP + disp32] -> 48 8D 0D disp32
        vtable_bytes = vtable_va.to_bytes(8, 'little')

        for i in range(len(text_data) - 7):
            # LEA RAX, [RIP+disp32] = 48 8D 05 XX XX XX XX
            if text_data[i:i+3] == b'\x48\x8d\x05':
                disp = int.from_bytes(text_data[i+3:i+7], 'little', signed=True)
                instr_va = text_start + i
                target = instr_va + 7 + disp
                if target == vtable_va:
                    print(f"    Found LEA RAX, [RIP+0x{disp:X}] at VA 0x{instr_va:X} (RVA 0x{instr_va - image_base:X}) -> vtable")
                    # Disassemble next 15 instructions
                    disasm_and_find_store(md, text_data, text_start, image_base, i, vtable_va)
            # LEA RCX, [RIP+disp32] = 48 8D 0D XX XX XX XX
            elif text_data[i:i+3] == b'\x48\x8d\x0d':
                disp = int.from_bytes(text_data[i+3:i+7], 'little', signed=True)
                instr_va = text_start + i
                target = instr_va + 7 + disp
                if target == vtable_va:
                    print(f"    Found LEA RCX, [RIP+0x{disp:X}] at VA 0x{instr_va:X} (RVA 0x{instr_va - image_base:X}) -> vtable")
                    disasm_and_find_store(md, text_data, text_start, image_base, i, vtable_va)
            # MOV RAX, [RIP+disp32] = 48 8B 05 XX XX XX XX
            elif text_data[i:i+3] == b'\x48\x8b\x05':
                disp = int.from_bytes(text_data[i+3:i+7], 'little', signed=True)
                instr_va = text_start + i
                target = instr_va + 7 + disp
                if target == vtable_va:
                    print(f"    Found MOV RAX, [RIP+0x{disp:X}] at VA 0x{instr_va:X} (RVA 0x{instr_va - image_base:X}) -> vtable")
                    disasm_and_find_store(md, text_data, text_start, image_base, i, vtable_va)
            # MOV RCX, [RIP+disp32] = 48 8B 0D XX XX XX XX
            elif text_data[i:i+3] == b'\x48\x8b\x0d':
                disp = int.from_bytes(text_data[i+3:i+7], 'little', signed=True)
                instr_va = text_start + i
                target = instr_va + 7 + disp
                if target == vtable_va:
                    print(f"    Found MOV RCX, [RIP+0x{disp:X}] at VA 0x{instr_va:X} (RVA 0x{instr_va - image_base:X}) -> vtable")
                    disasm_and_find_store(md, text_data, text_start, image_base, i, vtable_va)

def disasm_and_find_store(md, text_data, text_start, image_base, start_idx, vtable_va):
    """Disassemble from start_idx and look for MOV [RIP+disp32], RCX/RAX"""
    code_bytes = text_data[start_idx:start_idx+200]
    start_va = text_start + start_idx

    print(f"      Disassembling from 0x{start_va:X}:")
    count = 0
    for insn in md.disasm(code_bytes, start_va):
        bytes_str = " ".join(f"{b:02x}" for b in insn.bytes)
        print(f"        0x{insn.address:016X}  {bytes_str:<32}  {insn.mnemonic} {insn.op_str}")

        # Look for MOV [RIP+disp32], RCX or MOV [RIP+disp32], RAX
        # 48 89 0D disp32 = MOV [RIP+disp32], RCX
        # 48 89 05 disp32 = MOV [RIP+disp32], RAX
        if insn.mnemonic == 'mov' and '[' in insn.op_str and 'rip' in insn.op_str.lower():
            # Check if it's storing RCX or RAX to memory
            if ', rcx' in insn.op_str.lower() or ', rax' in insn.op_str.lower():
                # Extract the destination address
                # op_str format: "qword ptr [rip + 0x123456], rcx"
                import re
                match = re.search(r'\[rip\s*\+\s*0x([0-9a-fA-F]+)\]', insn.op_str)
                if match:
                    disp = int(match.group(1), 16)
                    dest_va = insn.address + insn.size + disp
                    dest_rva = dest_va - image_base
                    print(f"        >>> FOUND GLOBAL STORE: {insn.op_str}")
                    print(f"        >>> Destination VA: 0x{dest_va:X} (RVA 0x{dest_rva:X})")
                    print(f"        >>> This is g_pSimulationInstance RVA!")

                    # Verify it's in .data section
                    data_sec = None
                    pe = pefile.PE(EXE_PATH)
                    for section in pe.sections:
                        if section.Name.decode().strip('\x00') == '.data':
                            data_sec = section
                            break
                    if data_sec:
                        data_start = image_base + data_sec.VirtualAddress
                        data_end = data_start + data_sec.Misc_VirtualSize
                        if data_start <= dest_va < data_end:
                            print(f"        >>> CONFIRMED: In .data section (0x{data_start:X} - 0x{data_end:X})")
                        else:
                            print(f"        >>> WARNING: Not in .data section!")

        count += 1
        if count >= 20:
            break
        if insn.mnemonic == 'ret':
            break

if __name__ == "__main__":
    main()