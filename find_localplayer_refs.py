#!/usr/bin/env python3
"""
Find code references to LocalPlayer string and analyze GetLocalPlayer function
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

    print(f".text: RVA 0x{text_rva_base:08X}-0x{text_rva_base+text_sec['size']:08X} (size: {text_sec['size']:,} bytes)")
    print(f".rdata: RVA 0x{rdata_rva_base:08X}-0x{rdata_rva_base+rdata_sec['size']:08X}")

    # LocalPlayer string at RVA 0x0176D008 (found earlier)
    local_player_rva = 0x0176D008
    local_player_offset = rva_to_offset(local_player_rva)
    print(f"\nLocalPlayer string at RVA 0x{local_player_rva:08X}, file offset 0x{local_player_offset:08X}")
    print(f"Context: {data[local_player_offset-16:local_player_offset+64]}")

    # Find all code references to this string
    print("\n=== Code references to LocalPlayer string ===")
    refs = []
    target_bytes = struct.pack('<I', local_player_rva)
    for i in range(len(text_data) - 4):
        if text_data[i:i+4] == target_bytes:
            code_rva = text_rva_base + i
            refs.append(code_rva)

    print(f"Found {len(refs)} references")
    for code_rva in refs[:20]:
        offset = code_rva - text_rva_base
        # Show disassembly context
        start = max(0, offset - 32)
        end = min(len(text_data), offset + 48)
        context_bytes = text_data[start:end]
        # Try to decode as instructions
        print(f"  RVA 0x{code_rva:08X}: {context_bytes.hex()}")

    # Also search for GetLocalPlayer function pattern
    # We know GetLocalPlayer is a function that takes an int index and returns a controller interface
    # Let's search for the string "GetLocalPlayer" in rdata
    print("\n=== Searching for GetLocalPlayer string ===")
    for pattern in [b'GetLocalPlayer', b'getLocalPlayer', b'GetLocalPlayerByIndex', b'GetPlayerController']:
        pos = 0
        while True:
            idx = rdata_data.find(pattern, pos)
            if idx == -1:
                break
            rva = rdata_rva_base + idx
            print(f"  Found at RVA 0x{rva:08X}")
            # Find code refs
            target_bytes = struct.pack('<I', rva)
            for i in range(len(text_data) - 4):
                if text_data[i:i+4] == target_bytes:
                    code_rva = text_rva_base + i
                    offset = code_rva - text_rva_base
                    start = max(0, offset - 32)
                    end = min(len(text_data), offset + 48)
                    context_bytes = text_data[start:end]
                    print(f"    Code ref at RVA 0x{code_rva:08X}: {context_bytes.hex()}")
            pos = idx + len(pattern)

    # Now, let's look at the known GetLocalPlayer function
    # From earlier analysis: it's at RVA 0x1401EDA50 (relative to image base)
    # The image base for this PE is typically 0x140000000 for 64-bit
    # So the RVA would be 0x1EDA50
    print("\n=== Analyzing known GetLocalPlayer at RVA 0x001EDA50 ===")
    get_local_player_rva = 0x001EDA50
    offset = rva_to_offset(get_local_player_rva)
    if offset:
        print(f"  File offset: 0x{offset:08X}")
        # Disassemble first 100 bytes
        func_bytes = data[offset:offset+200]
        print(f"  Bytes: {func_bytes.hex()}")
        # Try to decode
        print(f"  As text: {func_bytes}")

if __name__ == "__main__":
    main()