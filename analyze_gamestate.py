#!/usr/bin/env python3
"""
Analyze GameState vtable and find GetLocalPlayer function.
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

def disasm_at(data, offset, max_instructions=40):
    pos = offset
    results = []
    for _ in range(max_instructions):
        if pos >= len(data):
            break
        byte = data[pos]

        if byte == 0xC3:
            results.append((pos, "ret"))
            break
        elif byte == 0xC2 and pos + 2 < len(data):
            imm = struct.unpack('<H', data[pos+1:pos+3])[0]
            results.append((pos, f"ret 0x{imm:04X}"))
            break
        elif byte == 0xE8 and pos + 4 < len(data):
            rel = struct.unpack('<i', data[pos+1:pos+5])[0]
            target = pos + 5 + rel
            results.append((pos, f"call 0x{target:08X}"))
            pos += 5
        elif byte == 0xFF and pos + 1 < len(data) and data[pos+1] == 0x15:
            if pos + 5 < len(data):
                disp = struct.unpack('<i', data[pos+2:pos+6])[0]
                target = pos + 6 + disp
                results.append((pos, f"call [rip+0x{disp:08X}] -> 0x{target:08X}"))
                pos += 6
        elif byte == 0x48 and pos + 1 < len(data) and data[pos+1] == 0x8B:
            if pos + 6 < len(data) and data[pos+2] == 0x05:
                disp = struct.unpack('<i', data[pos+3:pos+7])[0]
                target = pos + 7 + disp
                results.append((pos, f"mov rax, [rip+0x{disp:08X}] -> 0x{target:08X}"))
                pos += 7
        elif byte == 0x48 and pos + 1 < len(data) and data[pos+1] == 0x8D:
            if pos + 6 < len(data) and data[pos+2] == 0x05:
                disp = struct.unpack('<i', data[pos+3:pos+7])[0]
                target = pos + 7 + disp
                results.append((pos, f"lea rax, [rip+0x{disp:08X}] -> 0x{target:08X}"))
                pos += 7
        elif byte == 0x48 and pos + 1 < len(data) and data[pos+1] == 0x89:
            if pos + 6 < len(data) and data[pos+2] == 0x05:
                disp = struct.unpack('<i', data[pos+3:pos+7])[0]
                target = pos + 7 + disp
                results.append((pos, f"mov [rip+0x{disp:08X}], rax -> 0x{target:08X}"))
                pos += 7
        elif byte == 0xE9 and pos + 4 < len(data):
            rel = struct.unpack('<i', data[pos+1:pos+5])[0]
            target = pos + 5 + rel
            results.append((pos, f"jmp 0x{target:08X}"))
            pos += 5
        elif byte == 0x48 and pos + 2 < len(data) and data[pos+1] == 0x83 and data[pos+2] == 0xF9:
            if pos + 3 < len(data):
                imm = data[pos+3]
                results.append((pos, f"cmp rcx, 0x{imm:02X}"))
                pos += 4
        elif byte == 0x85 and pos + 1 < len(data) and data[pos+1] == 0xC9:
            results.append((pos, "test ecx, ecx"))
            pos += 2
        elif byte == 0x0F and pos + 1 < len(data) and 0x80 <= data[pos+1] <= 0x8F:
            if pos + 5 < len(data):
                rel = struct.unpack('<i', data[pos+2:pos+6])[0]
                target = pos + 6 + rel
                jcc_names = {0x80: "jo", 0x81: "jno", 0x82: "jb", 0x83: "jae",
                            0x84: "je", 0x85: "jne", 0x86: "jbe", 0x87: "ja",
                            0x88: "js", 0x89: "jns", 0x8A: "jp", 0x8B: "jnp",
                            0x8C: "jl", 0x8D: "jge", 0x8E: "jle", 0x8F: "jg"}
                jcc = jcc_names.get(data[pos+1], f"jcc_{data[pos+1]:02X}")
                results.append((pos, f"{jcc} 0x{target:08X}"))
                pos += 6
        elif byte >= 0x70 and byte <= 0x7F:
            if pos + 1 < len(data):
                rel = struct.unpack('<b', data[pos+1:pos+2])[0]
                target = pos + 2 + rel
                jcc_names = {0x70: "jo", 0x71: "jno", 0x72: "jb", 0x73: "jae",
                            0x74: "je", 0x75: "jne", 0x76: "jbe", 0x77: "ja",
                            0x78: "js", 0x79: "jns", 0x7A: "jp", 0x7B: "jnp",
                            0x7C: "jl", 0x7D: "jge", 0x7E: "jle", 0x7F: "jg"}
                jcc = jcc_names.get(byte, f"jcc_{byte:02X}")
                results.append((pos, f"{jcc} 0x{target:08X} (short)"))
                pos += 2
        elif byte == 0x48 and pos + 2 < len(data) and data[pos+1] == 0x8B:
            # MOV RAX, [RCX+...] or similar
            if pos + 3 < len(data):
                modrm = data[pos+2]
                results.append((pos, f"mov rax, [rcx+{modrm:02X}] (modrm={modrm:02X})"))
                pos += 3
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
    rdata_rva = 0
    rdata_raw = 0
    rdata_size = 0
    data_rva = 0
    data_raw = 0
    data_size = 0

    for i in range(num_sections):
        sec = sections_start + i * 40
        if sec + 40 > len(data):
            break
        name = data[sec:sec+8].rstrip(b'\0').decode('ascii', errors='ignore')
        sec_rva = struct.unpack('<I', data[sec+12:sec+16])[0]
        sec_size = struct.unpack('<I', data[sec+16:sec+20])[0]
        sec_raw = struct.unpack('<I', data[sec+20:sec+24])[0]
        if name == '.text':
            text_rva, text_raw, text_size = sec_rva, sec_raw, sec_size
        elif name == '.rdata':
            rdata_rva, rdata_raw, rdata_size = sec_rva, sec_raw, sec_size
        elif name == '.data':
            data_rva, data_raw, data_size = sec_rva, sec_raw, sec_size

    print(f".text: RVA=0x{text_rva:08X} Raw=0x{text_raw:08X} Size=0x{text_size:08X}")
    print(f".rdata: RVA=0x{rdata_rva:08X} Raw=0x{rdata_rva:08X} Size=0x{rdata_size:08X}")
    print(f".data: RVA=0x{data_rva:08X} Raw=0x{data_raw:08X} Size=0x{data_size:08X}")

    # 1. Analyze GameState vtable at RVA 0x01784BD0
    print("\n=== GameState vtable at RVA 0x01784BD0 ===")
    vtable_offset = rva_to_offset(data, 0x01784BD0)
    if vtable_offset:
        print(f"Vtable at file offset 0x{vtable_offset:08X}")
        for i in range(64):
            addr = vtable_offset + i * 8
            if addr + 8 <= len(data):
                val = struct.unpack('<Q', data[addr:addr+8])[0]
                if val != 0:
                    # Check if it points to code
                    if val > 0x140000000 and val < 0x142000000:
                        code_rva = val - 0x140000000
                        if text_rva <= code_rva < text_rva + text_size:
                            print(f"  [{i:2d}] 0x{addr:08X}: 0x{val:016X} -> CODE RVA 0x{code_rva:08X}")
                            # Disassemble this function
                            func_offset = rva_to_offset(data, code_rva)
                            if func_offset:
                                for instr in disasm_at(data, func_offset, 20):
                                    print(f"       0x{instr[0]:08X}: {instr[1]}")
                    elif rdata_rva <= val < rdata_rva + rdata_size or data_rva <= val < data_rva + data_size:
                        print(f"  [{i:2d}] 0x{addr:08X}: 0x{val:016X} -> DATA/RDATA")
                    else:
                        print(f"  [{i:2d}] 0x{addr:08X}: 0x{val:016X}")

    # 2. Search for functions that look like GetLocalPlayer(int controllerIndex) -> SimObjectCharacter*
    # Pattern: test ecx, ecx ; jle/jl ; mov rax, [rcx*8 + global] ; ret
    print("\n=== Searching for GetLocalPlayer-like functions ===")
    test_ecx = b'\x85\xC9'  # test ecx, ecx
    for m in re.finditer(test_ecx, data):
        pos = m.start()
        if text_raw <= pos < text_raw + text_size:
            # Look ahead for conditional jump
            ahead = data[pos:pos+48]
            # Check for jle (0F 8E), jl (0F 8C), jbe (0F 86), jb (0F 82), jg (0F 8F), jge (0F 8D), ja (0F 87), jae (0F 83)
            jcc_pos = -1
            for jcc_byte in [b'\x0F\x8E', b'\x0F\x8C', b'\x0F\x86', b'\x0F\x82', b'\x0F\x8F', b'\x0F\x8D', b'\x0F\x87', b'\x0F\x83']:
                idx = ahead.find(jcc_byte)
                if idx >= 0 and idx < 16:
                    jcc_pos = idx
                    break
            # Also check short jumps
            if jcc_pos == -1:
                for jcc_byte in [b'\x7E', b'\x7C', b'\x76', b'\x72', b'\x7F', b'\x7D', b'\x77', b'\x73']:
                    idx = ahead.find(jcc_byte)
                    if idx >= 0 and idx < 8:
                        jcc_pos = idx
                        break

            if jcc_pos >= 0:
                func_rva = get_rva_from_offset(data, pos)
                if func_rva:
                    print(f"\n  Candidate at RVA 0x{func_rva:08X} (file 0x{pos:08X})")
                    for instr in disasm_at(data, pos, 25):
                        print(f"    0x{instr[0]:08X}: {instr[1]}")

    # 3. Search for simple global pointer getters that might be the player pointer
    # Pattern: MOV RAX, [RIP+disp32] ; RET (8 bytes)
    print("\n=== Simple global pointer getters ===")
    getter_pattern = b'\x48\x8B\x05....\xC3'
    for m in re.finditer(getter_pattern, data):
        pos = m.start()
        if text_raw <= pos < text_raw + text_size:
            disp = struct.unpack('<i', data[pos+3:pos+7])[0]
            target_rva = get_rva_from_offset(data, pos + 7 + disp)
            func_rva = get_rva_from_offset(data, pos)
            if func_rva and target_rva:
                # Check if target is in .data or .rdata
                if (data_rva <= target_rva < data_rva + data_size) or (rdata_rva <= target_rva < rdata_rva + rdata_size):
                    print(f"  RVA 0x{func_rva:08X}: MOV RAX, [RIP+0x{disp:08X}] -> 0x{target_rva:08X} ({'.data' if data_rva <= target_rva < data_rva + data_size else '.rdata'})")

    # 4. Look for the player pointer global - search for references to SimObjectCharacter vtable
    print("\n=== Searching for global player pointer (points to SimObjectCharacter vtable) ===")
    # The SimObjectCharacter vtable is likely at a known RVA
    # Let's search for writes to globals that store vtable pointers

    # Search for MOV [RIP+disp32], RAX where RAX might hold a vtable
    mov_mem_rax = b'\x48\x89\x05'
    for m in re.finditer(mov_mem_rax, data):
        pos = m.start()
        if text_raw <= pos < text_raw + text_size:
            disp = struct.unpack('<i', data[pos+3:pos+7])[0]
            target_rva = get_rva_from_offset(data, pos + 7 + disp)
            func_rva = get_rva_from_offset(data, pos)
            if func_rva and target_rva and (data_rva <= target_rva < data_rva + data_size):
                # Look at preceding instructions to see what's in RAX
                print(f"  RVA 0x{func_rva:08X}: MOV [RIP+0x{disp:08X}] -> 0x{target_rva:08X} (.data), RAX = ?")
                # Disassemble backwards a bit
                for instr in disasm_at(data, max(0, pos-32), 15):
                    if instr[0] >= pos - 32:
                        print(f"    0x{instr[0]:08X}: {instr[1]}")

    data.close()

if __name__ == "__main__":
    main()