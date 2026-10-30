#!/usr/bin/env python3
"""
Find qSymbol constructor, Simulation::GetInstance, Simulation::GetSimObject
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

    print(f".text: RVA 0x{text_rva_base:08X}-0x{text_rva_base+text_sec['size']:08X}")
    print(f".rdata: RVA 0x{rdata_rva_base:08X}-0x{rdata_rva_base+rdata_sec['size']:08X}")

    # Search for qSymbol constructor pattern
    # qSymbol(const char*) - takes string pointer in RCX, computes hash, stores in mUID
    # Look for: function that takes RCX, does string hashing
    # CRC32 or similar hash function

    print("\n=== Searching for qSymbol string constructor ===")
    # Pattern: takes RCX (string ptr), loops through chars, computes hash
    # Common CRC32 pattern: loop with CRC table lookup

    # Search for CRC32 table in .rdata (256 entries of 4 bytes each = 1KB)
    crc32_table_found = False
    for i in range(0, len(rdata_data) - 1024, 4):
        # Check if this looks like a CRC32 table
        val0 = struct.unpack('<I', rdata_data[i:i+4])[0]
        val1 = struct.unpack('<I', rdata_data[i+4:i+8])[0]
        if val0 == 0x00000000 and val1 == 0x77073096:  # Standard CRC32 polynomial table start
            rva = rdata_rva_base + i
            print(f"  CRC32 table found at RVA 0x{rva:08X}")
            crc32_table_found = True
            break

    if not crc32_table_found:
        # Try other common CRC32 table values
        for i in range(0, len(rdata_data) - 1024, 4):
            val0 = struct.unpack('<I', rdata_data[i:i+4])[0]
            if val0 == 0xEDB88320:  # Reversed polynomial
                rva = rdata_rva_base + i
                print(f"  CRC32 polynomial at RVA 0x{rva:08X}")
                crc32_table_found = True
                break

    # Search for functions that reference the CRC32 table
    if crc32_table_found:
        crc_table_rva = rdata_rva_base + i
        target_bytes = struct.pack('<I', crc_table_rva)
        for i in range(len(text_data) - 4):
            if text_data[i:i+4] == target_bytes:
                code_rva = text_rva_base + i
                # Check if this is in a function (look for prologue nearby)
                print(f"  CRC32 table reference at RVA 0x{code_rva:08X}")

    # Search for Simulation::GetInstance pattern
    # Simple function: MOV RAX, [RIP+disp32]; RET
    # Returns a pointer to Simulation singleton
    print("\n=== Searching for Simulation::GetInstance (simple global getter) ===")
    # We already found global getters at 0x00152250+ - let's check their target functions
    getter_rvas = [0x00152250, 0x00152260, 0x00152270, 0x00152280, 0x00152290, 0x00184B10]

    for getter_rva in getter_rvas:
        offset = rva_to_offset(getter_rva)
        if offset:
            func_bytes = data[offset:offset+32]
            print(f"  Getter at RVA 0x{getter_rva:08X}: {func_bytes.hex()}")
            # Disassemble
            if func_bytes[0:3] == b'\x48\x8B\x05':  # MOV RAX, [RIP+disp32]
                disp = struct.unpack('<i', func_bytes[3:7])[0]
                target = getter_rva + 7 + disp
                print(f"    -> MOV RAX, [RIP+0x{disp:08X}] -> 0x{target:08X}")
                if func_bytes[7] == 0xC3:  # RET
                    print(f"    -> RET (simple getter)")

    # Search for GetSimObject pattern
    # Takes: Simulation* in RCX, qSymbol* in RDX, returns SimObject* in RAX
    # Should have: test rdx, rdx; jz; then some lookup; ret
    print("\n=== Searching for Simulation::GetSimObject pattern ===")
    # Look for function with pattern: test rdx, rdx; jz/jnz; ...; ret
    pattern = b'\x48\x85\xD2'  # test rdx, rdx
    for m in re.finditer(pattern, text_data):
        pos = m.start()
        code_rva = text_rva_base + pos
        # Look ahead for conditional jump and ret
        ahead = text_data[pos:pos+100]
        if b'\x0F\x84' in ahead[:64] or b'\x74' in ahead[:32] or b'\x75' in ahead[:32]:
            # Check if function returns in RAX (look for ret)
            if b'\xC3' in ahead[:100]:
                # This might be it - show disassembly
                print(f"  Candidate at RVA 0x{code_rva:08X}")
                # Show first 64 bytes
                print(f"    Bytes: {ahead[:64].hex()}")

    # Also search for functions that take two pointers and return a pointer
    # Pattern: function prologue + test rdx, rdx + ...
    print("\n=== Searching for GetSimObject with function prologue ===")
    # Function prologue: push rbx/push rsi/push rdi / sub rsp, imm
    prologue_patterns = [
        b'\x53\x48\x83\xEC',  # push rbx; sub rsp
        b'\x55\x48\x8B\xEC',  # push rbp; mov rbp, rsp
        b'\x48\x89\x5C\x24',  # mov [rsp+...], rbx
        b'\x48\x83\xEC',      # sub rsp
    ]

    # Let's search more specifically - look for the string "GetSimObject" in code references
    # First find the string
    sim_obj_strings = []
    for pattern in [b'GetSimObject', b'getSimObject', b'GetSimObjectByName', b'FindSimObject']:
        pos = 0
        while True:
            idx = rdata_data.find(pattern, pos)
            if idx == -1:
                break
            rva = rdata_rva_base + idx
            sim_obj_strings.append((rva, pattern))
            pos = idx + len(pattern)

    print(f"\nFound {len(sim_obj_strings)} GetSimObject-related strings in .rdata")
    for rva, pattern in sim_obj_strings:
        print(f"  String at RVA 0x{rva:08X}: {pattern}")
        # Find code refs
        target_bytes = struct.pack('<I', rva)
        for i in range(len(text_data) - 4):
            if text_data[i:i+4] == target_bytes:
                code_rva = text_rva_base + i
                print(f"    Code ref at RVA 0x{code_rva:08X}")
                # Show function start (look for prologue backwards)
                func_start = code_rva
                for back in range(min(128, code_rva - text_rva_base)):
                    check_rva = code_rva - back
                    check_offset = rva_to_offset(check_rva)
                    if check_offset and check_offset + 4 < len(data):
                        check_bytes = data[check_offset:check_offset+4]
                        # Check for prologue
                        if check_bytes[0] == 0x48 and check_bytes[1] == 0x83 and check_bytes[2] == 0xEC:  # sub rsp
                            func_start = check_rva
                            break
                        if check_bytes[0] == 0x55 and check_bytes[1] == 0x48 and check_bytes[2] == 0x8B and check_bytes[3] == 0xEC:  # push rbp; mov rbp, rsp
                            func_start = check_rva
                            break
                        if check_bytes[0] == 0x53:  # push rbx
                            # Check next bytes
                            if check_offset + 3 < len(data):
                                next_b = data[check_offset+1:check_offset+4]
                                if next_b[0] == 0x48 and next_b[1] == 0x83 and next_b[2] == 0xEC:  # push rbx; sub rsp
                                    func_start = check_rva
                                    break
                if func_start != code_rva:
                    print(f"    Function start at RVA 0x{func_start:08X}")
                    # Disassemble first 100 bytes
                    func_offset = rva_to_offset(func_start)
                    if func_offset:
                        func_bytes = data[func_offset:func_offset+128]
                        print(f"    Function bytes: {func_bytes.hex()[:128]}...")

    # Search for Simulation::GetInstance string
    print("\n=== Searching for Simulation::GetInstance string ===")
    for pattern in [b'GetInstance', b'getInstance', b's_Instance', b'm_Instance', b'Simulation::GetInstance']:
        pos = 0
        while True:
            idx = rdata_data.find(pattern, pos)
            if idx == -1:
                break
            rva = rdata_rva_base + idx
            print(f"  String at RVA 0x{rva:08X}: {rdata_data[max(0,idx-16):idx+32]}")
            pos = idx + len(pattern)

if __name__ == "__main__":
    main()