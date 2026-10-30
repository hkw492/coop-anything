#!/usr/bin/env python3
"""
Find GameState vtable and Simulation vtable
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

    text_sec = next(s for s in sections if s['name'] == '.text')
    text_data = data[text_sec['raw']:text_sec['raw'] + text_sec['size']]
    text_rva_base = text_sec['rva']
    rdata_sec = next(s for s in sections if s['name'] == '.rdata')
    rdata_data = data[rdata_sec['raw']:rdata_sec['raw'] + rdata_sec['size']]
    rdata_rva_base = rdata_sec['rva']

    # Check the exact vtable address from GameState constructor
    # lea rax, [rip+0x00C82968] at 0x00E285E0
    # RIP after = 0x00E285E6
    # Target = 0x00E285E6 + 0x00C82968 = 0x01AABF4E
    # Check aligned addresses
    for vtable_rva in [0x01AABF40, 0x01AABF48, 0x01AABF50, 0x01AABF58]:
        vtable_offset = vtable_rva - rdata_rva_base
        if 0 <= vtable_offset < len(rdata_data) - 8:
            print(f"\n=== Vtable at RVA 0x{vtable_rva:08X} ===")
            for i in range(20):
                if vtable_offset + i*8 + 8 <= len(rdata_data):
                    val = struct.unpack('<Q', rdata_data[vtable_offset + i*8:vtable_offset + i*8 + 8])[0]
                    if text_sec['rva'] <= val < text_sec['rva'] + text_sec['size']:
                        print(f"  [{i}] -> 0x{val:016X} (.text+0x{val-text_sec['rva']:X})")
                    else:
                        break
                else:
                    break

    # Search for vtables in .rdata whose first entry is called from 0x00C55270
    # 0x00C55270 does: mov rax, [rcx]; jmp [rax]
    # So it calls the first entry of the vtable of the object in RCX
    # Let's find vtables with many entries (Simulation should have many)
    print("\n=== Searching for vtables with 15+ entries in .rdata ===")
    text_rva_start = text_sec['rva']
    text_rva_end = text_sec['rva'] + text_sec['size']

    for i in range(0, len(rdata_data) - 8, 8):
        val = struct.unpack('<Q', rdata_data[i:i+8])[0]
        if text_rva_start <= val < text_rva_end:
            count = 1
            for j in range(1, 30):
                if i + j*8 + 8 <= len(rdata_data):
                    val2 = struct.unpack('<Q', rdata_data[i+j*8:i+j*8+8])[0]
                    if text_rva_start <= val2 < text_rva_end:
                        count += 1
                    else:
                        break
            if count >= 15:
                vtable_rva = rdata_rva_base + i
                print(f"\n  Vtable at RVA 0x{vtable_rva:08X} ({count} entries):")
                for j in range(min(count, 20)):
                    v = struct.unpack('<Q', rdata_data[i+j*8:i+j*8+8])[0]
                    print(f"    [{j}] -> 0x{v:016X} (.text+0x{v-text_rva_start:X})")
                # Check for nearby class name
                for back in range(1, 200):
                    if i - back >= 0 and rdata_data[i-back] == 0:
                        str_start = i - back - 1
                        while str_start > 0 and rdata_data[str_start-1] != 0:
                            str_start -= 1
                        s = rdata_data[str_start:i-back]
                        if len(s) > 4:
                            print(f"    Nearby string: {s}")
                        break

    # Also check the vtable at 0x01FA0E58 (found earlier with 15 entries)
    print("\n=== Vtable at RVA 0x01FA0E58 (15 entries) ===")
    vtable_rva = 0x01FA0E58
    vtable_offset = vtable_rva - rdata_rva_base
    if 0 <= vtable_offset < len(rdata_data) - 8:
        for i in range(20):
            if vtable_offset + i*8 + 8 <= len(rdata_data):
                val = struct.unpack('<Q', rdata_data[vtable_offset + i*8:vtable_offset + i*8 + 8])[0]
                if text_sec['rva'] <= val < text_sec['rva'] + text_sec['size']:
                    print(f"  [{i}] -> 0x{val:016X} (.text+0x{val-text_sec['rva']:X})")
                else:
                    break

if __name__ == "__main__":
    main()