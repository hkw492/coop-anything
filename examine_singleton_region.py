#!/usr/bin/env python3
"""
Examine the singleton region pointed to by global getters
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
    data_data = data[data_sec['raw']:data_sec['raw'] + data_sec['size']]
    data_rva_base = data_sec['rva']
    rdata_data = data[rdata_sec['raw']:rdata_sec['raw'] + rdata_sec['size']]
    rdata_rva_base = rdata_sec['rva']

    # The global getters at 0x00152250+ point to .data locations:
    # 0x020383B0 -> 0x1416A5420
    # 0x020383B8 -> 0x1416A5438
    # 0x020383D0 -> 0x1416A5480
    # 0x020383A0 -> 0x1416A5408
    # 0x020383C8 -> 0x1416A5468

    print("=== Global getter targets in .data ===")
    getter_targets = [
        (0x020383B0, "getter_1"),
        (0x020383B8, "getter_2"),
        (0x020383D0, "getter_3"),
        (0x020383A0, "getter_4"),
        (0x020383C8, "getter_5"),
    ]

    for target_rva, name in getter_targets:
        offset = target_rva - data_rva_base
        if 0 <= offset < len(data_data) - 8:
            ptr = struct.unpack('<Q', data_data[offset:offset+8])[0]
            print(f"  {name}: .data RVA 0x{target_rva:08X} -> 0x{ptr:016X}")
            # Check if this points to a vtable (pointer to .text)
            if text_sec['rva'] <= ptr < text_sec['rva'] + text_sec['size']:
                print(f"    -> Points to .text (vtable at 0x{ptr:016X})")

    # Examine the heap region 0x1416A5400 - 0x1416A5500
    print("\n=== Heap region 0x1416A5400 analysis ===")
    # We can't directly read heap, but we can see what the .data pointers point to
    # Let's look at the .data around these pointers
    for target_rva, name in getter_targets:
        offset = target_rva - data_rva_base
        # Show surrounding .data context
        start = max(0, offset - 64)
        end = min(len(data_data), offset + 64)
        context = data_data[start:end]
        print(f"\n  {name} context (.data RVA 0x{data_rva_base+start:08X}):")
        for i in range(0, len(context), 16):
            chunk = context[i:i+16]
            rva = data_rva_base + start + i
            vals = []
            for j in range(0, len(chunk), 8):
                if j + 8 <= len(chunk):
                    vals.append(struct.unpack('<Q', chunk[j:j+8])[0])
            print(f"    0x{rva:08X}: " + " ".join(f"{v:016X}" for v in vals))

    # Now let's look at the vtable candidates - pointers from .data to .text
    print("\n=== Vtable candidates (consecutive .text pointers in .data) ===")
    vtable_candidates = []
    for i in range(0, len(data_data) - 8, 8):
        val = struct.unpack('<Q', data_data[i:i+8])[0]
        if text_sec['rva'] <= val < text_sec['rva'] + text_sec['size']:
            rva = data_rva_base + i
            vtable_candidates.append((rva, val))

    # Group by target .text address
    from collections import defaultdict
    target_to_data = defaultdict(list)
    for rva, val in vtable_candidates:
        target_to_data[val].append(rva)

    # Show targets with multiple .data references (likely vtables used by multiple objects)
    print("\nVtables referenced from multiple .data locations:")
    for target, refs in sorted(target_to_data.items(), key=lambda x: -len(x[1])):
        if len(refs) > 1:
            print(f"  Vtable at .text 0x{target:016X} referenced from {len(refs)} .data locations:")
            for r in refs[:5]:
                print(f"    .data RVA 0x{r:08X}")

    # Look for vtable arrays (consecutive function pointers in .text)
    print("\n=== Scanning .text for vtable-like structures ===")
    # A vtable is an array of function pointers (8 bytes each) in .rdata or .text
    # Let's scan .rdata for arrays of .text pointers
    vtable_in_rdata = []
    for i in range(0, len(rdata_data) - 8, 8):
        val = struct.unpack('<Q', rdata_data[i:i+8])[0]
        if text_sec['rva'] <= val < text_sec['rva'] + text_sec['size']:
            rva = rdata_rva_base + i
            vtable_in_rdata.append((rva, val))

    # Find consecutive entries
    print(f"Found {len(vtable_in_rdata)} .rdata pointers to .text")
    for i in range(len(vtable_in_rdata) - 5):
        rva1, val1 = vtable_in_rdata[i]
        consecutive = True
        for j in range(1, 6):
            rva2, val2 = vtable_in_rdata[i+j]
            if rva2 != rva1 + j*8:
                consecutive = False
                break
        if consecutive:
            print(f"  Possible vtable at .rdata RVA 0x{rva1:08X}:")
            for j in range(6):
                rva, val = vtable_in_rdata[i+j]
                print(f"    [{j}] -> 0x{val:016X} (.text+0x{val-text_sec['rva']:X})")
            # Check if there's a type name nearby
            # Look backwards for a string
            string_offset = rva1 - rdata_rva_base - 32
            if string_offset > 0:
                for k in range(string_offset, rva1 - rdata_rva_base):
                    if rdata_data[k] == 0 and k > string_offset:
                        candidate = rdata_data[string_offset:k]
                        if len(candidate) > 4 and all(32 <= c <= 126 for c in candidate):
                            print(f"    Possible name: {candidate}")
                            break

if __name__ == "__main__":
    main()