#!/usr/bin/env python3
"""
Clean PE parser to search strings in sdhdship.exe
"""

import struct
from pathlib import Path

EXE_PATH = Path(r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe")

def main():
    with open(EXE_PATH, "rb") as f:
        data = f.read()

    # Verify MZ
    if data[:2] != b'MZ':
        print("Not an MZ file")
        return

    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    if data[pe_offset:pe_offset+4] != b'PE\0\0':
        print("Not a PE file")
        return

    num_sections = struct.unpack('<H', data[pe_offset+6:pe_offset+8])[0]
    opt_header_size = struct.unpack('<H', data[pe_offset+20:pe_offset+22])[0]
    sections_start = pe_offset + 24 + opt_header_size

    print(f"Num sections: {num_sections}")

    sections = []
    for i in range(num_sections):
        sec = sections_start + i * 40
        name = data[sec:sec+8].rstrip(b'\0').decode('ascii', errors='ignore')
        sec_rva = struct.unpack('<I', data[sec+12:sec+16])[0]
        sec_size = struct.unpack('<I', data[sec+16:sec+20])[0]
        sec_raw = struct.unpack('<I', data[sec+20:sec+24])[0]
        sections.append({'name': name, 'rva': sec_rva, 'size': sec_size, 'raw': sec_raw})
        print(f"Section {name}: RVA=0x{sec_rva:08X}, size=0x{sec_size:08X}, raw=0x{sec_raw:08X}")

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

    patterns = [
        b'Simulation',
        b'GetSimObject',
        b'GetInstance',
        b'LocalPlayer',
        b'PlayerController',
        b'WeiShen',
        b'qSymbol',
        b'SimObject',
    ]

    print("\n=== Matches ===")
    for pattern in patterns:
        pos = 0
        matches = []
        while True:
            idx = data.find(pattern, pos)
            if idx == -1:
                break
            rva = offset_to_rva(idx)
            sec_name = "unknown"
            for sec in sections:
                if sec['raw'] <= idx < sec['raw'] + sec['size']:
                    sec_name = sec['name']
                    break
            matches.append((idx, rva, sec_name))
            pos = idx + len(pattern)

        print(f"Pattern '{pattern.decode()}': {len(matches)} matches")
        for idx, rva, sec_name in matches[:5]:
            rva_str = f"0x{rva:08X}" if rva else "None"
            print(f"  raw=0x{idx:08X}, rva={rva_str}, section={sec_name}")

if __name__ == "__main__":
    main()
