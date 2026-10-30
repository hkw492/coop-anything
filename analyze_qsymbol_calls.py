#!/usr/bin/env python3
"""
Analyze qSymbol constructor and find its callers
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

    # Find qSymbol constructor function start (at 0x00E95E9A)
    rva = 0x00E95E9A
    func_start = rva
    for back in range(min(128, rva - text_rva_base)):
        check_rva = rva - back
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

    print(f"qSymbol constructor at RVA 0x{func_start:08X}")

    # Find CALL instructions targeting the qSymbol constructor
    print("\n=== Finding calls to qSymbol constructor ===")
    for i in range(len(text_data) - 5):
        if text_data[i] == 0xE8:
            rel = struct.unpack('<i', text_data[i+1:i+5])[0]
            call_addr = text_rva_base + i
            target = call_addr + 5 + rel
            if target == func_start:
                print(f"  CALL at RVA 0x{call_addr:08X} -> qSymbol ctor")
                # Show context (function containing this call)
                # Look backwards for function prologue
                func_start_call = call_addr
                for back in range(min(128, i)):
                    check_rva = call_addr - back
                    check_offset = rva_to_offset(check_rva)
                    if check_offset and check_offset + 4 <= len(data):
                        check_bytes = data[check_offset:check_offset+4]
                        if check_bytes[0] == 0x48 and check_bytes[1] == 0x83 and check_bytes[2] == 0xEC:
                            func_start_call = check_rva
                            break
                        if check_bytes[0] == 0x55 and check_bytes[1] == 0x48 and check_bytes[2] == 0x8B and check_bytes[3] == 0xEC:
                            func_start_call = check_rva
                            break
                        if check_bytes[0] == 0x53 and check_offset + 3 < len(data):
                            next_b = data[check_offset+1:check_offset+4]
                            if next_b[0] == 0x48 and next_b[1] == 0x83 and next_b[2] == 0xEC:
                                func_start_call = check_rva
                                break
                if func_start_call != call_addr:
                    print(f"    In function at RVA 0x{func_start_call:08X}")

    # Also search for LEA RCX/LEA RDX with string pointers before CALL
    print("\n=== Searching for qSymbol construction patterns (LEA RCX/RDX + CALL) ===")
    for i in range(len(text_data) - 10):
        # Pattern: LEA RCX, [RIP+disp32] followed by CALL
        if text_data[i:i+7] == b'\x48\x8D\x0D':  # LEA RCX, [RIP+disp32]
            disp = struct.unpack('<i', text_data[i+3:i+7])[0]
            lea_addr = text_rva_base + i
            string_rva = lea_addr + 7 + disp
            # Check if followed by CALL within 32 bytes
            for j in range(i+7, min(i+40, len(text_data)-5)):
                if text_data[j] == 0xE8:
                    rel = struct.unpack('<i', text_data[j+1:j+5])[0]
                    call_addr = text_rva_base + j
                    target = call_addr + 5 + rel
                    if target == func_start:
                        print(f"  LEA RCX, [RIP+0x{disp:08X}] -> string at 0x{string_rva:08X}")
                        print(f"  CALL at RVA 0x{call_addr:08X}")
                        # Check what string it is
                        string_offset = rva_to_offset(string_rva)
                        if string_offset:
                            s = data[string_offset:string_offset+32].split(b'\0')[0]
                            print(f"    String: {s}")
                        break

    # Also check LEA RDX pattern
    for i in range(len(text_data) - 10):
        if text_data[i:i+7] == b'\x48\x8D\x15':  # LEA RDX, [RIP+disp32]
            disp = struct.unpack('<i', text_data[i+3:i+7])[0]
            lea_addr = text_rva_base + i
            string_rva = lea_addr + 7 + disp
            for j in range(i+7, min(i+40, len(text_data)-5)):
                if text_data[j] == 0xE8:
                    rel = struct.unpack('<i', text_data[j+1:j+5])[0]
                    call_addr = text_rva_base + j
                    target = call_addr + 5 + rel
                    if target == func_start:
                        print(f"  LEA RDX, [RIP+0x{disp:08X}] -> string at 0x{string_rva:08X}")
                        print(f"  CALL at RVA 0x{call_addr:08X}")
                        string_offset = rva_to_offset(string_rva)
                        if string_offset:
                            s = data[string_offset:string_offset+32].split(b'\0')[0]
                            print(f"    String: {s}")
                        break

if __name__ == "__main__":
    main()