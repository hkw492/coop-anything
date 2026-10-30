#!/usr/bin/env python3
"""
Focused vtable scan for specific classes
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

    text_sec = None
    rdata_sec = None
    for sec in sections:
        if sec['name'] == '.text':
            text_sec = sec
        elif sec['name'] == '.rdata':
            rdata_sec = sec

    text_data = data[text_sec['raw']:text_sec['raw'] + text_sec['size']]
    text_rva_base = text_sec['rva']
    rdata_data = data[rdata_sec['raw']:rdata_sec['raw'] + rdata_sec['size']]
    rdata_rva_base = rdata_sec['rva']

    # Search for specific class names and check for vtables after them
    class_names = [
        b'UFG::Simulation',
        b'Simulation',
        b'UFG::GameState',
        b'GameState',
        b'UFG::SimObject',
        b'SimObject',
        b'UFG::SimObjectCharacter',
        b'SimObjectCharacter',
        b'UFG::PlayerController',
        b'PlayerController',
        b'UFG::LocalPlayer',
        b'LocalPlayer',
        b'UFG::World',
        b'World',
    ]

    print("=== Scanning for specific class names with vtables ===")
    for class_name in class_names:
        pos = 0
        while True:
            idx = rdata_data.find(class_name, pos)
            if idx == -1:
                break
            rva = rdata_rva_base + idx
            # Get full string
            start = idx
            while start > 0 and rdata_data[start-1] != 0:
                start -= 1
            end = idx + len(class_name)
            while end < len(rdata_data) and rdata_data[end] != 0:
                end += 1
            full_string = rdata_data[start:end]

            # Check for vtable after string
            offset = (end + 7) & ~7  # Align to 8 bytes
            vtable_ptrs = []
            for i in range(15):
                if offset + i*8 + 8 <= len(rdata_data):
                    val = struct.unpack('<Q', rdata_data[offset + i*8:offset + i*8 + 8])[0]
                    if text_sec['rva'] <= val < text_sec['rva'] + text_sec['size']:
                        vtable_ptrs.append(val)
                    else:
                        break

            if len(vtable_ptrs) >= 3:
                print(f"\n  Class: {full_string} at RVA 0x{rva:08X}")
                print(f"  Vtable at RVA 0x{rva_rva_base + offset:08X} ({len(vtable_ptrs)} entries):")
                for j, v in enumerate(vtable_ptrs[:8]):
                    print(f"    [{j}] -> 0x{v:016X} (.text+0x{v-text_sec['rva']:X})")

            pos = idx + len(class_name)

if __name__ == "__main__":
    main()