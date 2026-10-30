#!/usr/bin/env python3
"""
Find the actual C++ GetLocalPlayer function by searching for:
1. Functions that return a pointer to SimObjectCharacter
2. Cross-references to player-related data
3. The function that the script "get_local_player" calls
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

def get_rva_from_offset(data, offset):
    """Convert file offset to RVA."""
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
        sec_raw = struct.unpack('<I', data[sec+20:sec+24])[0]
        sec_rva = struct.unpack('<I', data[sec+12:sec+16])[0]
        sec_size = struct.unpack('<I', data[sec+16:sec+20])[0]
        if sec_raw <= offset < sec_raw + sec_size:
            return sec_rva + (offset - sec_raw)
    return None

def find_function_starts(data, text_section_rva, text_section_raw, text_section_size):
    """Find function prologues in the .text section."""
    functions = []
    # Common x64 function prologues:
    # 48 89 5C 24 XX          mov [rsp+XX], rbx
    # 48 89 74 24 XX          mov [rsp+XX], rsi
    # 48 89 7C 24 XX          mov [rsp+XX], rdi
    # 55                      push rbp
    # 48 8B EC                mov rbp, rsp
    # 48 83 EC XX             sub rsp, XX
    # 48 81 EC XX XX XX XX    sub rsp, XXXXXXXX

    prologue_patterns = [
        b'\x48\x89\x5C\x24',  # mov [rsp+XX], rbx
        b'\x48\x89\x74\x24',  # mov [rsp+XX], rsi
        b'\x48\x89\x7C\x24',  # mov [rsp+XX], rdi
        b'\x55',              # push rbp
        b'\x48\x8B\xEC',      # mov rbp, rsp
        b'\x48\x83\xEC',      # sub rsp, imm8
        b'\x48\x81\xEC',      # sub rsp, imm32
    ]

    # Search for prologue patterns in .text section
    for pattern in prologue_patterns:
        for m in re.finditer(pattern, data):
            pos = m.start()
            if text_section_raw <= pos < text_section_raw + text_section_size:
                rva = get_rva_from_offset(data, pos)
                if rva:
                    functions.append((rva, pos, pattern[:4].hex()))
    return functions

def disasm_at(data, offset, max_instructions=20):
    """Simple disassembly at offset."""
    pos = offset
    results = []
    for _ in range(max_instructions):
        if pos >= len(data):
            break
        byte = data[pos]

        # RET
        if byte == 0xC3:
            results.append((pos, "ret"))
            break
        # RET imm16
        elif byte == 0xC2 and pos + 2 < len(data):
            imm = struct.unpack('<H', data[pos+1:pos+3])[0]
            results.append((pos, f"ret 0x{imm:04X}"))
            break
        # CALL rel32
        elif byte == 0xE8 and pos + 4 < len(data):
            rel = struct.unpack('<i', data[pos+1:pos+5])[0]
            target = pos + 5 + rel
            results.append((pos, f"call 0x{target:08X}"))
            pos += 5
        # CALL [RIP+disp32]
        elif byte == 0xFF and pos + 1 < len(data) and data[pos+1] == 0x15:
            if pos + 5 < len(data):
                disp = struct.unpack('<i', data[pos+2:pos+6])[0]
                target = pos + 6 + disp
                results.append((pos, f"call [rip+0x{disp:08X}] -> 0x{target:08X}"))
                pos += 6
        # MOV RAX, [RIP+disp32]
        elif byte == 0x48 and pos + 1 < len(data) and data[pos+1] == 0x8B:
            if pos + 6 < len(data) and data[pos+2] == 0x05:
                disp = struct.unpack('<i', data[pos+3:pos+7])[0]
                target = pos + 7 + disp
                results.append((pos, f"mov rax, [rip+0x{disp:08X}] -> 0x{target:08X}"))
                pos += 7
        # LEA RAX, [RIP+disp32]
        elif byte == 0x48 and pos + 1 < len(data) and data[pos+1] == 0x8D:
            if pos + 6 < len(data) and data[pos+2] == 0x05:
                disp = struct.unpack('<i', data[pos+3:pos+7])[0]
                target = pos + 7 + disp
                results.append((pos, f"lea rax, [rip+0x{disp:08X}] -> 0x{target:08X}"))
                pos += 7
        # MOV [RIP+disp32], RAX
        elif byte == 0x48 and pos + 1 < len(data) and data[pos+1] == 0x89:
            if pos + 6 < len(data) and data[pos+2] == 0x05:
                disp = struct.unpack('<i', data[pos+3:pos+7])[0]
                target = pos + 7 + disp
                results.append((pos, f"mov [rip+0x{disp:08X}], rax -> 0x{target:08X}"))
                pos += 7
        else:
            pos += 1
    return results

def main():
    data = read_exe()

    # Get .text section info
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    num_sections = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
    opt_header_size = struct.unpack('<H', data[pe_offset+20:pe_offset+22])[0]
    sections_start = pe_offset + 24 + opt_header_size

    text_rva = 0
    text_raw = 0
    text_size = 0

    for i in range(num_sections):
        sec = sections_start + i * 40
        if sec + 40 > len(data):
            break
        name = data[sec:sec+8].rstrip(b'\0').decode('ascii', errors='ignore')
        sec_rva = struct.unpack('<I', data[sec+12:sec+16])[0]
        sec_size = struct.unpack('<I', data[sec+16:sec+20])[0]
        sec_raw = struct.unpack('<I', data[sec+20:sec+24])[0]
        if name == '.text':
            text_rva = sec_rva
            text_raw = sec_raw
            text_size = sec_size
            print(f".text section: RVA=0x{text_rva:08X}, Raw=0x{text_raw:08X}, Size=0x{text_size:08X}")
            break

    # Search for functions that might be GetLocalPlayer
    # Look for functions that:
    # 1. Return a pointer (RAX at return)
    # 2. Access a global pointer in .data/.rdata
    # 3. Are relatively simple (few instructions)

    print("\n=== Searching for candidate GetLocalPlayer functions ===")

    # Pattern: function that does MOV RAX, [RIP+disp32] ; RET
    # This is a simple global pointer getter
    simple_getter = b'\x48\x8B\x05....\xC3'
    candidates = []
    for m in re.finditer(simple_getter, data):
        pos = m.start()
        if text_raw <= pos < text_raw + text_size:
            disp = struct.unpack('<i', data[pos+3:pos+7])[0]
            target_rva = get_rva_from_offset(data, pos + 7 + disp)
            func_rva = get_rva_from_offset(data, pos)
            if func_rva and target_rva:
                # Check if target is in .data or .rdata (global pointer)
                candidates.append((func_rva, pos, target_rva))

    print(f"Found {len(candidates)} simple getter functions")

    # Now filter candidates - the target should be a pointer to SimObjectCharacter
    # which would be in the heap, so the global would point to a pointer
    # Let's look at what each target points to

    # Also, let's search for the string "get_local_player" and find what function it maps to
    # In SkookumScript, script functions are mapped to C++ functions via a table
    # Let's search for the script function table

    print("\n=== Analyzing script function table area ===")
    script_table_offset = 0x017B2B28  # Area around get_local_player
    script_table_rva = get_rva_from_offset(data, script_table_offset)
    print(f"Script table at file offset 0x{script_table_offset:08X} -> RVA 0x{script_table_rva:08X}")

    # Look at the structure around the string table
    # Usually there's an array of structures: { string_ptr, function_ptr, ... }
    for i in range(0, 200, 8):
        addr = script_table_offset + i
        if addr + 8 <= len(data):
            val = struct.unpack('<Q', data[addr:addr+8])[0]
            if val != 0:
                # Check if it points to code (.text section)
                target_rva = get_rva_from_offset(data, val - (0x140000000 if val > 0x140000000 else 0))
                if target_rva and text_rva <= target_rva < text_rva + text_size:
                    print(f"  0x{addr:08X}: 0x{val:016X} -> RVA 0x{target_rva:08X} (CODE!)")

    # Let's also search for functions that might be called "GetLocalPlayer" or similar
    # Look for functions that take an int (controller index) and return SimObjectCharacter*
    # Typical signature: SimObjectCharacter* GetLocalPlayer(int controllerIndex)
    # In x64 calling convention: RCX = controllerIndex, RAX = return value

    print("\n=== Searching for functions taking int and returning pointer ===")
    # Look for functions that start with testing RCX and then accessing a global array
    # Pattern: test ecx, ecx / jg / mov rax, [rcx*8 + global]

    # Search for "test ecx, ecx" followed by conditional jump and memory access
    test_ecx = b'\x85\xC9'  # test ecx, ecx
    for m in re.finditer(test_ecx, data):
        pos = m.start()
        if text_raw <= pos < text_raw + text_size:
            # Look ahead for conditional jump and global access
            ahead = data[pos:pos+32]
            if b'\x0F\x8F' in ahead or b'\x0F\x8E' in ahead or b'\x7F' in ahead or b'\x7E' in ahead:
                func_rva = get_rva_from_offset(data, pos)
                if func_rva:
                    print(f"  Candidate at RVA 0x{func_rva:08X} (file 0x{pos:08X})")
                    # Disassemble
                    for instr in disasm_at(data, pos, 15):
                        print(f"    0x{instr[0]:08X}: {instr[1]}")
                    print()

    # Search for "SimObjectCharacter" vtable or RTTI
    print("\n=== Searching for SimObjectCharacter RTTI/vtable ===")
    # RTTI for SimObjectCharacter would be like ".?AVSimObjectCharacter@UFG@@"
    for m in re.finditer(b'SimObjectCharacter', data):
        pos = m.start()
        rva = get_rva_from_offset(data, pos)
        if rva:
            print(f"  RVA 0x{rva:08X} (file 0x{pos:08X})")
            # Look at surrounding bytes for vtable or RTTI structure
            for i in range(-32, 32, 8):
                addr = pos + i
                if 0 <= addr < len(data) - 8:
                    val = struct.unpack('<Q', data[addr:addr+8])[0]
                    if val != 0:
                        target_rva = get_rva_from_offset(data, val - (0x140000000 if val > 0x140000000 else 0))
                        if target_rva and text_rva <= target_rva < text_rva + text_size:
                            print(f"    0x{addr:08X}: points to code at RVA 0x{target_rva:08X}")

    data.close()

if __name__ == "__main__":
    main()