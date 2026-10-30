#!/usr/bin/env python3
"""
Search for Simulation class, GetSimObject, GetInstance, and player-related strings in sdhdship.exe
"""

import mmap
import struct
import re
from pathlib import Path

EXE_PATH = Path(r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe")

def read_exe():
    with open(EXE_PATH, "rb") as f:
        return mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

def get_section_info(data):
    if data[:2] != b'MZ':
        return None
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    if pe_offset + 4 > len(data) or data[pe_offset:pe_offset+4] != b'PE\0\0':
        return None
    num_sections = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
    opt_header_size = struct.unpack('<H', data[pe_offset+20:pe_offset+22])[0]
    sections_start = pe_offset + 24 + opt_header_size

    sections = {}
    for i in range(num_sections):
        sec = sections_start + i * 40
        if sec + 40 > len(data):
            break
        name = data[sec:sec+8].rstrip(b'\0').decode('ascii', errors='ignore')
        sec_rva = struct.unpack('<I', data[sec+12:sec+16])[0]
        sec_size = struct.unpack('<I', data[sec+16:sec+20])[0]
        sec_raw = struct.unpack('<I', data[sec+20:sec+24])[0]
        sections[name] = {'rva': sec_rva, 'size': sec_size, 'raw': sec_raw}
    return sections

def get_rva_from_offset(sections, offset):
    for name, sec in sections.items():
        if sec['raw'] <= offset < sec['raw'] + sec['size']:
            return sec['rva'] + (offset - sec['raw'])
    return None

def search_strings(data, patterns):
    """Search for byte patterns in data"""
    results = {}
    for pattern in patterns:
        results[pattern] = []
        for m in re.finditer(re.escape(pattern), data):
            pos = m.start()
            rva = get_rva_from_offset(sections, pos)
            if rva:
                results[pattern].append((rva, pos))
    return results

def main():
    global sections
    data = read_exe()
    sections = get_section_info(data)

    if not sections:
        print("Failed to parse PE sections")
        return

    print("Sections:")
    for name, sec in sections.items():
        print(f"  {name}: RVA=0x{sec['rva']:08X}-0x{sec['rva']+sec['size']:08X}")

    # Search for relevant strings
    patterns = [
        b'Simulation',
        b'SIMULATION',
        b'simulation',
        b'GetSimObject',
        b'getSimObject',
        b'GetInstance',
        b'getInstance',
        b'LocalPlayer',
        b'localPlayer',
        b'PlayerController',
        b'playerController',
        b'WeiShen',
        b'WEISHEN',
        b'Wei Shen',
        b'qSymbol',
        b'SimObject',
        b'simObject',
    ]

    print("\n=== String search ===")
    results = search_strings(data, patterns)
    for pattern, matches in results.items():
        if matches:
            print(f"\n  '{pattern.decode()}': {len(matches)} matches")
            for rva, pos in matches[:10]:  # Limit to first 10
                section = None
                for name, sec in sections.items():
                    if sec['rva'] <= rva < sec['rva'] + sec['size']:
                        section = name
                        break
                print(f"    RVA 0x{rva:08X} (file 0x{pos:08X}) in {section}")

    data.close()

if __name__ == "__main__":
    main()