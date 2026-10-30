#!/usr/bin/env python3
"""
Find qSymbol constructor and analyze Simulation singleton getters
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

    # CRC32 table at RVA 0x01AC14C0
    crc_table_rva = 0x01AC14C0
    crc_table_offset = rva_to_offset(crc_table_rva)
    if crc_table_offset:
        print(f"CRC32 table at file offset 0x{crc_table_offset:08X}")
        # Verify table
        table_data = rdata_data[crc_table_offset - rdata_sec['raw']:crc_table_offset - rdata_sec['raw'] + 16]
        print(f"  First 4 entries: {table_data.hex()}")

    # Find functions that reference the CRC32 table (likely qSymbol constructor)
    print("\n=== Functions referencing CRC32 table ===")
    target_bytes = struct.pack('<I', crc_table_rva)
    refs = []
    for i in range(len(text_data) - 4):
        if text_data[i:i+4] == target_bytes:
            code_rva = text_rva_base + i
            refs.append(code_rva)

    print(f"Found {len(refs)} references to CRC32 table")
    for code_rva in refs[:20]:
        offset = code_rva - text_rva_base
        # Look backwards for function start
        func_start = code_rva
        for back in range(min(128, offset)):
            check_rva = code_rva - back
            check_offset = rva_to_offset(check_rva)
            if check_offset and check_offset + 4 <= len(data):
                check_bytes = data[check_offset:check_offset+4]
                if check_bytes[0] == 0x48 and check_bytes[1] == 0x83 and check_bytes[2] == 0xEC:  # sub rsp
                    func_start = check_rva
                    break
                if check_bytes[0] == 0x55 and check_bytes[1] == 0x48 and check_bytes[2] == 0x8B and check_bytes[3] == 0xEC:  # push rbp; mov rbp, rsp
                    func_start = check_rva
                    break
                if check_bytes[0] == 0x53 and check_offset + 3 < len(data):  # push rbx
                    next_b = data[check_offset+1:check_offset+4]
                    if next_b[0] == 0x48 and next_b[1] == 0x83 and next_b[2] == 0xEC:  # push rbx; sub rsp
                        func_start = check_rva
                        break
        if func_start != code_rva:
            func_offset = rva_to_offset(func_start)
            if func_offset:
                func_bytes = data[func_offset:func_offset+80]
                print(f"  Function at RVA 0x{func_start:08X} (ref at 0x{code_rva:08X}):")
                print(f"    {func_bytes.hex()}")

    # Now check the global getters at 0x00152250+ - what do they point to?
    print("\n=== Analyzing global getters at 0x00152250+ ===")
    getter_rvas = [0x00152250, 0x00152260, 0x00152270, 0x00152280, 0x00152290]
    for getter_rva in getter_rvas:
        offset = rva_to_offset(getter_rva)
        if offset:
            func_bytes = data[offset:offset+16]
            print(f"  RVA 0x{getter_rva:08X}: {func_bytes.hex()}")
            if func_bytes[0:3] == b'\x48\x8B\x05':
                disp = struct.unpack('<i', func_bytes[3:7])[0]
                target = getter_rva + 7 + disp
                print(f"    -> Points to .data RVA 0x{target:08X}")
                # Read the pointer value at that .data location
                data_offset = rva_to_offset(target)
                if data_offset:
                    ptr_val = struct.unpack('<Q', data[data_offset:data_offset+8])[0]
                    print(f"    -> Contains heap pointer: 0x{ptr_val:016X}")
                    # Check if this heap pointer has a vtable
                    # Read first 8 bytes of the heap object (vtable pointer)
                    heap_offset = ptr_val  # We can't directly read heap, but we know the value
                    # The heap object's first qword is its vtable
                    # We can check if this vtable is in .text
                    if text_sec['rva'] <= heap_offset < text_sec['rva'] + text_sec['size']:
                        print(f"    -> Vtable in .text at 0x{heap_offset:016X}")
                    else:
                        print(f"    -> Vtable at 0x{heap_offset:016X} (not in .text)")

    # Search for qSymbol constructor - takes const char* in RCX
    # Pattern: function that loads CRC32 table, processes string in RCX
    print("\n=== Searching for qSymbol::qSymbol(const char*) ===")
    # Look for functions with CRC32 table reference that take RCX as string pointer
    # The function should:
    # 1. Check if RCX is null
    # 2. Loop through string bytes
    # 3. Use CRC32 table to compute hash
    # 4. Store in RAX/EAX

    # Let's look at the functions that reference CRC32 table more closely
    for code_rva in refs[:10]:
        func_offset = rva_to_offset(code_rva)
        if not func_offset:
            continue
        # Look at the function around the reference
        func_start = code_rva
        for back in range(min(128, code_rva - text_rva_base)):
            check_rva = code_rva - back
            check_offset = rva_to_offset(check_rva)
            if check_offset and check_offset + 4 <= len(data):
                check_bytes = data[check_offset:check_offset+4]
                if check_bytes[0] == 0x48 and check_bytes[1] == 0x83 and check_bytes[2] == 0xEC:
                    func_start = check_rva
                    break
                if check_bytes[0] == 0x55 and check_bytes[1] == 0x48 and check_bytes[2] == 0x8B and check_bytes[3] == 0xEC:
                    func_start = check_rva
                    break
                if check_bytes[0] == 0x53 and check_offset + 3 < len(data):
                    next_b = data[check_offset+1:check_offset+4]
                    if next_b[0] == 0x48 and next_b[1] == 0x83 and next_b[2] == 0xEC:
                        func_start = check_rva
                        break
        if func_start != code_rva:
            func_offset = rva_to_offset(func_start)
            if func_offset:
                func_bytes = data[func_offset:func_offset+120]
                # Check if it looks like a string hashing function
                # Should have: test rcx, rcx; jz; loop; ret
                if b'\x48\x85\xC9' in func_bytes[:32] and b'\xC3' in func_bytes[:100]:
                    print(f"\n  Candidate qSymbol constructor at RVA 0x{func_start:08X}:")
                    print(f"    {func_bytes[:80].hex()}")

if __name__ == "__main__":
    main()