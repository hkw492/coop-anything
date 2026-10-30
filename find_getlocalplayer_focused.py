#!/usr/bin/env python3
"""
Focused search for GetLocalPlayer function.
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
        elif byte == 0x48 and pos + 2 < len(data) and data[pos+1] == 0x8B:
            if pos + 3 < len(data):
                modrm = data[pos+2]
                # Check if it's [rcx*8 + disp32] or similar
                if (modrm & 0xC7) == 0x04:  # SIB byte follows
                    if pos + 7 < len(data):
                        sib = data[pos+3]
                        disp = struct.unpack('<i', data[pos+4:pos+8])[0]
                        base = sib & 0x7
                        index = (sib >> 3) & 0x7
                        scale = (sib >> 6) & 0x3
                        results.append((pos, f"mov rax, [rcx*{(1<<scale)} + r{index}*{(1<<scale)} + 0x{disp:X}]"))
                        pos += 8
                    else:
                        results.append((pos, f"mov rax, [rcx+{modrm:02X}] (with SIB)"))
                        pos += 3
                else:
                    results.append((pos, f"mov rax, [rcx+{modrm:02X}]"))
                    pos += 3
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
        else:
            pos += 1
    return results

def main():
    data = read_exe()

    # Get section info
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    num_sections = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
    opt_header_size = struct.unpack('<H', data[pe_offset+20:pe_offset+22])[0]
    sections_start = pe_offset + 24 + opt_header_size

    text_rva = 0
    text_raw = 0
    text_size = 0
    data_rva = 0
    data_raw = 0
    data_size = 0
    rdata_rva = 0
    rdata_raw = 0
    rdata_size = 0

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

    print(f".text: RVA=0x{text_rva:08X}-0x{text_rva+text_size:08X}")
    print(f".data: RVA=0x{data_rva:08X}-0x{data_rva+data_size:08X}")
    print(f".rdata: RVA=0x{rdata_rva:08X}-0x{rdata_rva+rdata_size:08X}")

    # Search for GetLocalPlayer pattern: test ecx, ecx ; conditional jump ; array access ; ret
    print("\n=== Searching for GetLocalPlayer pattern ===")
    test_ecx = b'\x85\xC9'  # test ecx, ecx
    candidates = []

    for m in re.finditer(test_ecx, data):
        pos = m.start()
        if text_raw <= pos < text_raw + text_size:
            # Look ahead up to 64 bytes for the pattern
            ahead = data[pos:pos+64]

            # Check for conditional jump within first 16 bytes
            has_jcc = False
            jcc_offset = 0
            for jcc_bytes in [b'\x0F\x8E', b'\x0F\x8C', b'\x0F\x86', b'\x0F\x82',
                             b'\x0F\x8F', b'\x0F\x8D', b'\x0F\x87', b'\x0F\x83',
                             b'\x7E', b'\x7C', b'\x76', b'\x72', b'\x7F', b'\x7D', b'\x77', b'\x73']:
                idx = ahead.find(jcc_bytes)
                if idx >= 0 and idx < 16:
                    has_jcc = True
                    jcc_offset = idx
                    break

            if has_jcc:
                # Now check if there's a memory access pattern after the jump
                # Look for mov rax, [rcx*8 + disp] or mov rax, [rax + rcx*8] etc.
                func_rva = get_rva_from_offset(data, pos)
                if func_rva:
                    candidates.append((func_rva, pos))

    print(f"Found {len(candidates)} candidates with test ecx, ecx + conditional jump")

    # Filter to those that look like array access with RCX as index
    good_candidates = []
    for func_rva, pos in candidates:
        instrs = disasm_at(data, pos, 30)
        # Check for array access pattern
        has_array_access = False
        has_ret = False
        for instr in instrs:
            if 'rcx' in instr[1].lower() and ('[' in instr[1] or 'mov rax' in instr[1].lower()):
                has_array_access = True
            if 'ret' in instr[1].lower():
                has_ret = True
        if has_array_access and has_ret:
            good_candidates.append((func_rva, pos, instrs))

    print(f"\n=== {len(good_candidates)} Strong candidates (array access + ret) ===")
    for func_rva, pos, instrs in good_candidates[:20]:
        print(f"\n  Candidate at RVA 0x{func_rva:08X} (file 0x{pos:08X}):")
        for instr in instrs:
            print(f"    0x{instr[0]:08X}: {instr[1]}")

    # Also search for simple getter: MOV RAX, [RIP+disp32] ; RET
    print("\n=== Simple global getters (MOV RAX, [RIP+disp32]; RET) ===")
    getter_pattern = b'\x48\x8B\x05....\xC3'
    for m in re.finditer(getter_pattern, data):
        pos = m.start()
        if text_raw <= pos < text_raw + text_size:
            disp = struct.unpack('<i', data[pos+3:pos+7])[0]
            target_rva = get_rva_from_offset(data, pos + 7 + disp)
            func_rva = get_rva_from_offset(data, pos)
            if func_rva and target_rva:
                if (data_rva <= target_rva < data_rva + data_size) or (rdata_rva <= target_rva < rdata_rva + rdata_size):
                    print(f"  RVA 0x{func_rva:08X}: MOV RAX, [RIP+0x{disp:08X}] -> 0x{target_rva:08X} ({'.data' if data_rva <= target_rva < data_rva + data_size else '.rdata'})")

    # Search for "GetLocalPlayer" or "get_local_player" in debug strings
    print("\n=== Searching for player-related function names ===")
    for pattern in [b'GetLocalPlayer', b'get_local_player', b'LocalPlayer', b'local_player',
                    b'GetPlayer', b'get_player', b'PlayerController', b'player_controller']:
        for m in re.finditer(pattern, data):
            pos = m.start()
            rva = get_rva_from_offset(data, pos)
            if rva:
                print(f"  '{pattern.decode()}' at RVA 0x{rva:08X} (file 0x{pos:08X})")
                # Show context
                context = data[max(0,pos-32):pos+64]
                print(f"    Context: {context}")

    data.close()

if __name__ == "__main__":
    main()