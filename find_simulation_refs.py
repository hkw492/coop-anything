#!/usr/bin/env python3
"""
Find code references to Simulation string and global getters
"""

import struct
from pathlib import Path

EXE_PATH = Path(r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe")

def main():
    with open(EXE_PATH, "rb") as f:
        data = f.read()

    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    num_sections = struct.unpack('<H', data[pe_offset+6:pe_offset+8])[0]
    opt_header_size = struct.unpack('<H', data[pe_offset+20:pe_offset+22])[0]
    sections_start = pe_offset + 24 + opt_header_size

    sections = []
    for i in range(num_sections):
        sec = sections_start + i * 40
        name = data[sec:sec+8].rstrip(b'\0').decode('ascii', errors='ignore')
        sec_rva = struct.unpack('<I', data[sec+12:sec+16])[0]
        sec_size = struct.unpack('<I', data[sec+16:sec+20])[0]
        sec_raw = struct.unpack('<I', data[sec+20:sec+24])[0]
        sections.append({'name': name, 'rva': sec_rva, 'size': sec_size, 'raw': sec_raw})

    def rva_to_offset(rva):
        for sec in sections:
            if sec['rva'] <= rva < sec['rva'] + sec['size']:
                return sec['raw'] + (rva - sec['rva'])
        return None

    def offset_to_rva(offset):
        for sec in sections:
            if sec['raw'] <= offset < sec['raw'] + sec['size']:
                return sec['rva'] + (offset - sec['raw'])
        return None

    # Find "Simulation" string location - we know it's at RVA 0x016BF394 from clean search
    sim_rva = 0x016BF394
    sim_offset = rva_to_offset(sim_rva)
    print(f"Simulation string at RVA 0x{sim_rva:08X}, file offset 0x{sim_offset:08X}")
    print(f"Context: {data[sim_offset-32:sim_offset+64]}")

    # Find all references to this address in .text section
    text_sec = None
    for sec in sections:
        if sec['name'] == '.text':
            text_sec = sec
            break

    text_data = data[text_sec['raw']:text_sec['raw'] + text_sec['size']]
    text_rva_base = text_sec['rva']

    print(f"\n=== Code references to Simulation string (0x{sim_rva:08X}) ===")
    refs = []
    for i in range(len(text_data) - 4):
        val = struct.unpack('<I', text_data[i:i+4])[0]
        if val == sim_rva:
            code_rva = text_rva_base + i
            refs.append(code_rva)
            # Show some context
            start = max(0, i - 16)
            end = min(len(text_data), i + 32)
            print(f"  RVA 0x{code_rva:08X}: ...{text_data[start:end].hex()}...")

    print(f"Found {len(refs)} references")

    # Now find simple global getters: MOV RAX, [RIP+disp32]; RET
    # Pattern: 48 8B 05 xx xx xx xx C3
    print("\n=== Simple global getters (MOV RAX, [RIP+disp32]; RET) ===")
    getter_pattern = b'\x48\x8B\x05....\xC3'
    import re
    for m in re.finditer(getter_pattern, text_data):
        pos = m.start()
        code_rva = text_rva_base + pos
        disp = struct.unpack('<i', text_data[pos+3:pos+7])[0]
        target_rva = code_rva + 7 + disp

        # Check if target is in .data or .rdata
        target_section = None
        for sec in sections:
            if sec['rva'] <= target_rva < sec['rva'] + sec['size']:
                target_section = sec['name']
                break

        if target_section in ('.data', '.rdata'):
            print(f"  RVA 0x{code_rva:08X}: MOV RAX, [RIP+0x{disp:08X}] -> 0x{target_rva:08X} ({target_section})")

    # Also search for pattern with possible REX prefix variations
    # 48 8B 05 xx xx xx xx C3 - mov rax, [rip+disp32]; ret
    # 48 8B 05 xx xx xx xx 48 89 05 xx xx xx xx C3 - mov rax, [rip+disp32]; mov [rip+disp32], rax; ret
    print("\n=== Additional getter patterns ===")
    patterns = [
        (b'\x48\x8B\x05....\xC3', 'mov rax, [rip+disp32]; ret'),
        (b'\x48\xA1....\xC3', 'mov rax, [abs32]; ret (rare)'),
    ]
    for pattern, desc in patterns:
        for m in re.finditer(pattern, text_data):
            pos = m.start()
            code_rva = text_rva_base + pos
            print(f"  RVA 0x{code_rva:08X}: {desc} - bytes: {text_data[pos:pos+16].hex()}")

if __name__ == "__main__":
    main()