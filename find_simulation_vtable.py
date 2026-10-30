#!/usr/bin/env python3
"""
Search for Simulation-related code and analyze global getters
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

    # Search for "Simulation" strings in .rdata and find code refs
    print("=== Searching for 'Simulation' strings in .rdata with code refs ===")
    for s in [b'Simulation', b'simulation', b'UFG::Simulation']:
        pos = 0
        while True:
            idx = rdata_data.find(s, pos)
            if idx == -1:
                break
            rva = rdata_rva_base + idx
            # Find code refs by scanning text for RIP-relative references
            target_bytes = struct.pack('<I', rva)
            refs = []
            for i in range(len(text_data) - 4):
                if text_data[i:i+4] == target_bytes:
                    code_rva = text_rva_base + i
                    refs.append(code_rva)
            if refs:
                print(f"\n  String at RVA 0x{rva:08X}: {rdata_data[max(0,idx-16):idx+48]}")
                for code_rva in refs[:5]:
                    print(f"    Code ref at RVA 0x{code_rva:08X}")
                    # Find function containing this
                    for back in range(min(128, code_rva - text_rva_base)):
                        check_rva = code_rva - back
                        check_offset = rva_to_offset(check_rva)
                        if check_offset and check_offset + 4 <= len(data):
                            check_bytes = data[check_offset:check_offset+4]
                            if check_bytes[0] == 0x48 and check_bytes[1] == 0x83 and check_bytes[2] == 0xEC:
                                print(f"      In function at RVA 0x{check_rva:08X}")
                                break
                            if check_bytes[0] == 0x55 and check_bytes[1] == 0x48 and check_bytes[2] == 0x8B and check_bytes[3] == 0xEC:
                                print(f"      In function at RVA 0x{check_rva:08X}")
                                break
                            if check_bytes[0] == 0x53 and check_offset + 3 < len(data):
                                next_b = data[check_offset+1:check_offset+4]
                                if next_b[0] == 0x48 and next_b[1] == 0x83 and next_b[2] == 0xEC:
                                    print(f"      In function at RVA 0x{check_rva:08X}")
                                    break
            pos = idx + len(s)

    # Analyze the 5 global getters at 0x00152250+
    print("\n=== Analyzing global getters at 0x00152250+ ===")
    getter_rvas = [0x00152250, 0x00152260, 0x00152270, 0x00152280, 0x00152290]
    heap_ptrs = []
    for getter_rva in getter_rvas:
        offset = rva_to_offset(getter_rva)
        if offset:
            func_bytes = data[offset:offset+16]
            if func_bytes[0:3] == b'\x48\x8B\x05':  # MOV RAX, [RIP+disp32]
                disp = struct.unpack('<i', func_bytes[3:7])[0]
                target = getter_rva + 7 + disp
                data_offset = rva_to_offset(target)
                if data_offset:
                    ptr_val = struct.unpack('<Q', data[data_offset:data_offset+8])[0]
                    heap_ptrs.append((getter_rva, ptr_val))
                    print(f"  Getter 0x{getter_rva:08X} -> .data 0x{target:08X} -> heap 0x{ptr_val:016X}")

    # The heap pointers are: 0x1416A5420, 0x1416A5438, 0x1416A5480, 0x1416A5408, 0x1416A5468
    # These are heap addresses. Their vtables are at offset 0 in the heap object.
    # We can't read heap directly, but we know the vtable pointers should be in .rdata
    # Let's look at vtables in .rdata that have the right number of entries for Simulation

    print("\n=== Scanning .rdata for vtables with many entries (likely managers/singletons) ===")
    text_rva_start = text_sec['rva']
    text_rva_end = text_sec['rva'] + text_sec['size']

    # Scan for vtables (sequences of .text pointers)
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
            if count >= 10:  # Simulation should have many virtual functions
                print(f"  Vtable at RVA 0x{rdata_rva_base + i:08X} ({count} entries):")
                for j in range(min(count, 15)):
                    v = struct.unpack('<Q', rdata_data[i+j*8:i+j*8+8])[0]
                    print(f"    [{j}] -> 0x{v:016X} (.text+0x{v-text_rva_start:X})")
                # Check for nearby class name
                # Look backwards for string
                for back in range(1, 200):
                    if i - back >= 0 and rdata_data[i-back] == 0:
                        # Found null terminator, check for string before it
                        str_start = i - back - 1
                        while str_start > 0 and rdata_data[str_start-1] != 0:
                            str_start -= 1
                        s = rdata_data[str_start:i-back]
                        if len(s) > 4 and b'Simulation' in s:
                            print(f"    Class name nearby: {s}")
                        break

if __name__ == "__main__":
    main()