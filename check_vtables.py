#!/usr/bin/env python3
"""
Check specific addresses and find vtables with names
"""

import struct
import re
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

    text_sec = None
    data_sec = None
    rdata_sec = None
    for sec in sections:
        if sec['name'] == '.text':
            text_sec = sec
        elif sec['name'] == '.data':
            data_sec = sec
        elif sec['name'] == '.rdata':
            rdata_sec = sec

    text_data = data[text_sec['raw']:text_sec['raw'] + text_sec['size']]
    text_rva_base = text_sec['rva']
    rdata_data = data[rdata_sec['raw']:rdata_sec['raw'] + rdata_sec['size']]
    rdata_rva_base = rdata_sec['rva']

    # Check 0x140152190 - it's in .text
    print("=== Function at .text RVA 0x00152190 ===")
    offset = rva_to_offset(0x00152190)
    if offset:
        func_bytes = data[offset:offset+100]
        print(f"  Bytes: {func_bytes.hex()}")
        # Try to decode first few instructions
        p = 0
        while p < min(50, len(func_bytes)):
            byte = func_bytes[p]
            addr = 0x00152190 + p
            if byte == 0xC3:
                print(f"  0x{addr:08X}: ret")
                break
            elif byte == 0xE8 and p + 4 < len(func_bytes):
                rel = struct.unpack('<i', func_bytes[p+1:p+5])[0]
                target = addr + 5 + rel
                print(f"  0x{addr:08X}: call 0x{target:08X}")
                p += 5
            elif byte == 0x48 and p + 1 < len(func_bytes):
                next_byte = func_bytes[p+1]
                if next_byte == 0x8B and p + 2 < len(func_bytes):
                    modrm = func_bytes[p+2]
                    if modrm == 0x05 and p + 6 < len(func_bytes):
                        disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                        target = addr + 7 + disp
                        print(f"  0x{addr:08X}: mov rax, [rip+0x{disp:08X}] -> 0x{target:08X}")
                        p += 7
                    else:
                        p += 1
                elif next_byte == 0x89 and p + 2 < len(func_bytes):
                    modrm = func_bytes[p+2]
                    if modrm == 0xE5:
                        print(f"  0x{addr:08X}: mov rbp, rsp")
                        p += 3
                    elif modrm == 0xC1:
                        print(f"  0x{addr:08X}: mov rax, rcx")
                        p += 3
                    else:
                        p += 1
                elif next_byte == 0xB8:  # MOV RAX, imm32
                    if p + 5 < len(func_bytes):
                        imm = struct.unpack('<I', func_bytes[p+2:p+6])[0]
                        print(f"  0x{addr:08X}: mov rax, 0x{imm:08X}")
                        p += 6
                    else:
                        p += 1
                elif next_byte == 0xC7:
                    p += 1
                else:
                    p += 1
            elif byte == 0x55:
                print(f"  0x{addr:08X}: push rbp")
                p += 1
            elif byte == 0x53:
                print(f"  0x{addr:08X}: push rbx")
                p += 1
            elif byte == 0x56:
                print(f"  0x{addr:08X}: push rsi")
                p += 1
            elif byte == 0x57:
                print(f"  0x{addr:08X}: push rdi")
                p += 1
            else:
                p += 1

    # Check 0x1401520D0 - also in .text
    print("\n=== Function at .text RVA 0x001520D0 ===")
    offset = rva_to_offset(0x001520D0)
    if offset:
        func_bytes = data[offset:offset+100]
        print(f"  Bytes: {func_bytes.hex()}")
        p = 0
        while p < min(50, len(func_bytes)):
            byte = func_bytes[p]
            addr = 0x001520D0 + p
            if byte == 0xC3:
                print(f"  0x{addr:08X}: ret")
                break
            elif byte == 0xE8 and p + 4 < len(func_bytes):
                rel = struct.unpack('<i', func_bytes[p+1:p+5])[0]
                target = addr + 5 + rel
                print(f"  0x{addr:08X}: call 0x{target:08X}")
                p += 5
            elif byte == 0x48 and p + 1 < len(func_bytes):
                next_byte = func_bytes[p+1]
                if next_byte == 0x8B and p + 2 < len(func_bytes):
                    modrm = func_bytes[p+2]
                    if modrm == 0x05 and p + 6 < len(func_bytes):
                        disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                        target = addr + 7 + disp
                        print(f"  0x{addr:08X}: mov rax, [rip+0x{disp:08X}] -> 0x{target:08X}")
                        p += 7
                    else:
                        p += 1
                else:
                    p += 1
            elif byte == 0x55:
                print(f"  0x{addr:08X}: push rbp")
                p += 1
            elif byte == 0x53:
                print(f"  0x{addr:08X}: push rbx")
                p += 1
            else:
                p += 1

    # Now scan .rdata for vtables with type names nearby
    print("\n=== Scanning .rdata for vtables with type names ===")
    # Look for patterns: type name string followed by vtable (array of .text pointers)

    # First, find all strings in .rdata that look like class names
    class_patterns = [
        b'Simulation',
        b'SimObject',
        b'GameState',
        b'World',
        b'Player',
        b'Character',
        b'Manager',
        b'System',
        b'Component',
        b'Controller',
    ]

    string_locations = []
    for pattern in class_patterns:
        pos = 0
        while True:
            idx = rdata_data.find(pattern, pos)
            if idx == -1:
                break
            rva = rdata_rva_base + idx
            # Get full string
            start = idx
            while start > 0 and rdata_data[start-1] != 0:
                start -= 1
            end = idx + len(pattern)
            while end < len(rdata_data) and rdata_data[end] != 0:
                end += 1
            full_string = rdata_data[start:end]
            string_locations.append((rva, full_string))
            pos = idx + len(pattern)

    # Sort by RVA
    string_locations.sort(key=lambda x: x[0])

    print(f"Found {len(string_locations)} candidate class name strings")
    for rva, s in string_locations[:50]:
        # Check if followed by vtable (array of .text pointers)
        offset = rva - rdata_rva_base + len(s) + 1
        # Align to 8 bytes
        offset = (offset + 7) & ~7
        vtable_ptrs = []
        for i in range(10):
            if offset + i*8 + 8 <= len(rdata_data):
                val = struct.unpack('<Q', rdata_data[offset + i*8:offset + i*8 + 8])[0]
                if text_sec['rva'] <= val < text_sec['rva'] + text_sec['size']:
                    vtable_ptrs.append(val)
                else:
                    break
        if len(vtable_ptrs) >= 3:
            print(f"  String at RVA 0x{rva:08X}: {s}")
            print(f"    Possible vtable at RVA 0x{rva_rva_base + offset:08X}: {len(vtable_ptrs)} entries")
            for j, v in enumerate(vtable_ptrs[:5]):
                print(f"      [{j}] -> 0x{v:016X} (.text+0x{v-text_sec['rva']:X})")

if __name__ == "__main__":
    main()