#!/usr/bin/env python3
"""
Analyze .data section pointers to find singletons like Simulation
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

    data_sec = None
    for sec in sections:
        if sec['name'] == '.data':
            data_sec = sec
            break

    data_data = data[data_sec['raw']:data_sec['raw'] + data_sec['size']]
    data_rva_base = data_sec['rva']

    print(f".data: RVA 0x{data_rva_base:08X}-0x{data_rva_base+data_sec['size']:08X} (size: {data_sec['size']:,} bytes)")

    # Scan all 8-byte values in .data that look like valid pointers
    print("\n=== All .data 8-byte values that look like heap pointers ===")
    heap_pointers = []
    for i in range(0, len(data_data) - 8, 8):
        val = struct.unpack('<Q', data_data[i:i+8])[0]
        # Heap pointers typically: 0x0000000100000000 to 0x00007FFFFFFFFFFF
        # Module base is around 0x140000000
        if 0x0000000100000000 <= val <= 0x00007FFFFFFFFFFF:
            rva = data_rva_base + i
            heap_pointers.append((rva, val))

    print(f"Found {len(heap_pointers)} potential heap pointers")

    # Group by target address to find unique objects
    target_counts = {}
    for rva, val in heap_pointers:
        # Round to 16-byte alignment for grouping
        aligned = val & ~0xF
        if aligned not in target_counts:
            target_counts[aligned] = []
        target_counts[aligned].append(rva)

    # Show targets with multiple references (likely important objects)
    print("\n=== Heap objects with multiple references ===")
    for target, refs in sorted(target_counts.items(), key=lambda x: -len(x[1])):
        if len(refs) > 1:
            print(f"  Target 0x{target:016X}: {len(refs)} refs at RVAs {[f'0x{r:08X}' for r in refs[:5]]}")
            # Show context around first ref
            first_rva = refs[0]
            offset = first_rva - data_rva_base
            context = data_data[max(0,offset-32):offset+32]
            print(f"    Context: {context.hex()}")

    # Also look for vtables - they point to .text section
    print("\n=== .data pointers to .text (possible vtables) ===")
    text_sec = None
    for sec in sections:
        if sec['name'] == '.text':
            text_sec = sec
            break

    text_start = text_sec['rva']
    text_end = text_sec['rva'] + text_sec['size']

    vtable_candidates = []
    for i in range(0, len(data_data) - 8, 8):
        val = struct.unpack('<Q', data_data[i:i+8])[0]
        if text_start <= val < text_end:
            rva = data_rva_base + i
            vtable_candidates.append((rva, val))

    print(f"Found {len(vtable_candidates)} pointers to .text section")
    for rva, val in vtable_candidates[:30]:
        print(f"  .data RVA 0x{rva:08X} -> 0x{val:016X} (.text +0x{val-text_start:X})")

    # Look for arrays of vtable pointers (consecutive .text pointers)
    print("\n=== Possible vtable arrays (consecutive .text pointers) ===")
    for i in range(len(vtable_candidates) - 2):
        rva1, val1 = vtable_candidates[i]
        rva2, val2 = vtable_candidates[i+1]
        rva3, val3 = vtable_candidates[i+2]
        if rva2 == rva1 + 8 and rva3 == rva2 + 8:
            print(f"  Array at .data RVA 0x{rva1:08X}: 0x{val1:016X}, 0x{val2:016X}, 0x{val3:016X}")
            # Check how long the array is
            length = 3
            for j in range(i+3, min(i+20, len(vtable_candidates))):
                rva_next, val_next = vtable_candidates[j]
                if rva_next == rva1 + length * 8:
                    length += 1
                else:
                    break
            if length > 3:
                print(f"    Length: {length} entries")

if __name__ == "__main__":
    main()