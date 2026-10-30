#!/usr/bin/env python3
"""
Find the actual GetLocalPlayer function by analyzing code around the "get_local_player" string.
"""

import mmap
import struct
import re
from pathlib import Path

EXE_PATH = Path(r"C:\HK\COOP\coop-anything\local\sleeping-dogs-test\sdhdship.exe")

def read_exe():
    with open(EXE_PATH, "rb") as f:
        return mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

def rva_to_offset(data, rva):
    """Convert RVA to file offset."""
    if data[:2] != b'MZ':
        return None
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    if pe_offset + 4 > len(data) or data[pe_offset:pe_offset+4] != b'PE\0\0':
        return None
    num_sections = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
    opt_header_size = struct.unpack('<H', data[pe_offset+20:pe_offset+22])[0]
    sections_start = pe_offset + 24 + opt_header_size

    for i in range(num_sections):
        sec = sections_start + i * 40
        if sec + 40 > len(data):
            break
        sec_rva = struct.unpack('<I', data[sec+12:sec+16])[0]
        sec_size = struct.unpack('<I', data[sec+16:sec+20])[0]
        sec_raw = struct.unpack('<I', data[sec+20:sec+24])[0]
        if sec_rva <= rva < sec_rva + sec_size:
            return sec_raw + (rva - sec_rva)
    return None

def disasm_simple(data, offset, max_bytes=64):
    """Very simple x64 disassembly - just to see instructions near a location."""
    # This is extremely simplified - just for pattern recognition
    result = []
    pos = offset
    for _ in range(10):
        if pos >= len(data) or pos >= offset + max_bytes:
            break
        byte = data[pos]
        # Common patterns
        if byte == 0x48:  # REX.W prefix
            if pos + 2 < len(data):
                next_byte = data[pos + 1]
                if next_byte == 0x8B:  # MOV RAX, [RIP+disp32]
                    if pos + 6 < len(data):
                        disp = struct.unpack('<i', data[pos+3:pos+7])[0]
                        target_rva = (pos + 7) + disp
                        result.append(f"  0x{pos:08X}: 48 8B 05 ?? ?? ?? ??  mov rax, [rip+0x{disp:08X}] -> RVA 0x{target_rva:08X}")
                        pos += 7
                        continue
                elif next_byte == 0x89:  # MOV [RIP+disp32], RAX
                    if pos + 6 < len(data):
                        disp = struct.unpack('<i', data[pos+3:pos+7])[0]
                        target_rva = (pos + 7) + disp
                        result.append(f"  0x{pos:08X}: 48 89 05 ?? ?? ?? ??  mov [rip+0x{disp:08X}], rax -> RVA 0x{target_rva:08X}")
                        pos += 7
                        continue
        elif byte == 0xC3:  # RET
            result.append(f"  0x{pos:08X}: C3                    ret")
            pos += 1
            break
        elif byte == 0xE8:  # CALL rel32
            if pos + 4 < len(data):
                rel = struct.unpack('<i', data[pos+1:pos+5])[0]
                target_rva = (pos + 5) + rel
                result.append(f"  0x{pos:08X}: E8 ?? ?? ?? ??      call 0x{target_rva:08X}")
                pos += 5
                continue
        elif byte == 0xFF and pos + 1 < len(data) and data[pos+1] == 0x15:  # CALL [RIP+disp32]
            if pos + 5 < len(data):
                disp = struct.unpack('<i', data[pos+2:pos+6])[0]
                target_rva = (pos + 6) + disp
                result.append(f"  0x{pos:08X}: FF 15 ?? ?? ?? ??   call [rip+0x{disp:08X}] -> RVA 0x{target_rva:08X}")
                pos += 6
                continue
        pos += 1
    return result

def main():
    data = read_exe()

    # The string "get_local_player" is at file offset 0x017B2B68
    # Let's find what references this string
    string_offset = 0x017B2B68
    string_rva = string_offset  # approximation

    print(f"Analyzing 'get_local_player' string at file offset 0x{string_offset:08X}")

    # Search for references to this string (RIP-relative LEA or direct address)
    # The string address in memory would be: image_base + string_rva
    # But we need to find code that loads this address

    # Look for LEA instructions that might reference this string
    # LEA RAX, [RIP+disp32] where disp32 = string_rva - (instruction_addr + 7)
    # We'll search for the string address being used

    # First, let's look at the area around the string to see if there's code nearby
    print(f"\n=== Bytes around 'get_local_player' string (offset 0x{string_offset:08X}) ===")
    for i in range(-64, 64, 16):
        addr = string_offset + i
        if 0 <= addr < len(data):
            hex_bytes = ' '.join(f'{b:02X}' for b in data[addr:addr+16])
            ascii_bytes = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data[addr:addr+16])
            marker = " <-- STRING" if i == 0 else ""
            print(f"  0x{addr:08X}: {hex_bytes:<48} {ascii_bytes}{marker}")

    # Now search for code that references this string address
    # The string's virtual address = image_base + string_rva
    # We'll search for the relative offset pattern
    print("\n=== Searching for references to get_local_player string ===")

    # The string is at file offset 0x017B2B68
    # In memory, if image base is 0x140000000 (typical), string VA = 0x140000000 + 0x017B2B68 = 0x1417B2B68
    # But we need to find the actual image base from PE header
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    image_base = struct.unpack('<Q', data[pe_offset+30:pe_offset+38])[0]
    print(f"Image base: 0x{image_base:016X}")

    string_va = image_base + string_offset  # This assumes string is at same RVA as file offset
    # Actually need to convert properly
    string_rva_proper = string_offset  # This is approximate; need proper section mapping
    string_va_proper = image_base + string_rva_proper
    print(f"String VA (approx): 0x{string_va_proper:016X}")

    # Search for RIP-relative references to this area
    # LEA RAX, [RIP+disp32] -> 48 8D 05 disp32
    # Or MOV RAX, [RIP+disp32] -> 48 8B 05 disp32

    # Let's look at the Ghidra analysis results for cross-references
    # But first, let's search for the pattern 48 8D 05 (LEA RAX, [RIP+disp32])
    print("\n=== Searching for LEA RAX, [RIP+disp32] patterns ===")
    lea_pattern = b'\x48\x8D\x05'
    for m in re.finditer(lea_pattern, data):
        pos = m.start()
        if pos + 7 <= len(data):
            disp = struct.unpack('<i', data[pos+3:pos+7])[0]
            target_rva = (pos + 7) + disp
            # Check if target is near our string
            if abs(target_rva - string_rva_proper) < 0x1000:
                print(f"  0x{pos:08X}: LEA RAX, [RIP+0x{disp:08X}] -> RVA 0x{target_rva:08X} (near string!)")

    # Also search for the function name in the export table or debug info
    print("\n=== Searching for 'GetLocalPlayer' function name in exports/debug ===")
    for m in re.finditer(b'GetLocalPlayer', data):
        print(f"  Found at file offset 0x{m.start():08X}")

    # Search for the function that might be the getter
    # Look for simple getter pattern: MOV RAX, [RIP+offset] ; RET
    # which compiles to: 48 8B 05 XX XX XX XX C3
    print("\n=== Searching for simple getter pattern (MOV RAX, [RIP+offset]; RET) ===")
    getter_pattern = b'\x48\x8B\x05....\xC3'
    for m in re.finditer(getter_pattern, data):
        pos = m.start()
        disp = struct.unpack('<i', data[pos+3:pos+7])[0]
        target_rva = (pos + 7) + disp
        # Check what's at the target - if it's in .data/.rdata section, might be a global pointer
        print(f"  0x{pos:08X}: MOV RAX, [RIP+0x{disp:08X}] -> RVA 0x{target_rva:08X}; RET")
        # Disassemble a bit more context
        for line in disasm_simple(data, max(0, pos-32)):
            print(line)
        print()

    # Look for the string "is_local_player" at 0x017AE630
    print("\n=== Analyzing 'is_local_player' string at 0x017AE630 ===")
    string_offset2 = 0x017AE630
    for i in range(-64, 64, 16):
        addr = string_offset2 + i
        if 0 <= addr < len(data):
            hex_bytes = ' '.join(f'{b:02X}' for b in data[addr:addr+16])
            ascii_bytes = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data[addr:addr+16])
            marker = " <-- STRING" if i == 0 else ""
            print(f"  0x{addr:08X}: {hex_bytes:<48} {ascii_bytes}{marker}")

    data.close()

if __name__ == "__main__":
    main()