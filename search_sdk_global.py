#!/usr/bin/env python3
"""
Search for code accessing the SDK's GetLocalPlayer global at RVA 0x209E170.
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
            elif pos + 3 < len(data):
                modrm = data[pos+2]
                if (modrm & 0xC7) == 0x04:  # SIB
                    if pos + 7 < len(data):
                        sib = data[pos+3]
                        disp = struct.unpack('<i', data[pos+4:pos+8])[0]
                        base = sib & 0x7
                        index = (sib >> 3) & 0x7
                        scale = (sib >> 6) & 0x3
                        scale_val = 1 << scale
                        regs = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi']
                        index_str = f"{regs[index]}*{scale_val}" if index != 4 else ""
                        base_str = regs[base]
                        if index_str:
                            addr = f"{base_str}+{index_str}+0x{disp:X}"
                        else:
                            addr = f"{base_str}+0x{disp:X}"
                        results.append((pos, f"mov rax, [{addr}]"))
                        pos += 8
                    else:
                        results.append((pos, f"mov rax, [r{modrm&7}+{modrm>>3}] (SIB)"))
                        pos += 3
                else:
                    results.append((pos, f"mov rax, [r{modrm&7}+{modrm>>3}]"))
                    pos += 3
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

    # SDK's GetLocalPlayer global at RVA 0x209E170
    sdk_global_rva = 0x209E170
    sdk_global_offset = rva_to_offset(data, sdk_global_rva)
    print(f"SDK Global at RVA 0x{sdk_global_rva:08X} (file 0x{sdk_global_offset:08X})")

    if sdk_global_offset:
        val = struct.unpack('<Q', data[sdk_global_offset:sdk_global_offset+8])[0]
        print(f"  Value: 0x{val:016X}")

    # Search for code that accesses this global via RIP-relative addressing
    # MOV RAX, [RIP+disp32] where target = sdk_global_rva
    # LEA RAX, [RIP+disp32] where target = sdk_global_rva
    # MOV [RIP+disp32], RAX where target = sdk_global_rva

    print("\n=== Searching for RIP-relative access to SDK global ===")

    # For each RIP-relative instruction in .text, check if it targets the SDK global
    rip_patterns = [
        (b'\x48\x8B\x05', 'MOV RAX, [RIP+disp32]'),
        (b'\x48\x8D\x05', 'LEA RAX, [RIP+disp32]'),
        (b'\x48\x89\x05', 'MOV [RIP+disp32], RAX'),
        (b'\x48\x8B\x0D', 'MOV RCX, [RIP+disp32]'),
        (b'\x48\x8D\x0D', 'LEA RCX, [RIP+disp32]'),
        (b'\x48\x89\x0D', 'MOV [RIP+disp32], RCX'),
    ]

    for pattern, desc in rip_patterns:
        for m in re.finditer(pattern, data):
            pos = m.start()
            if text_raw <= pos < text_raw + text_size:
                if pos + 7 <= len(data):
                    disp = struct.unpack('<i', data[pos+3:pos+7])[0]
                    target_rva = get_rva_from_offset(data, pos + 7 + disp)
                    if target_rva == sdk_global_rva:
                        func_rva = get_rva_from_offset(data, pos)
                        print(f"  RVA 0x{func_rva:08X} (file 0x{pos:08X}): {desc} -> SDK Global!")
                        # Disassemble function
                        for instr in disasm_at(data, max(0, pos-32), 30):
                            if instr[0] >= pos-32:
                                print(f"    0x{instr[0]:08X}: {instr[1]}")

    # Also search for direct absolute addressing (less common in x64)
    # MOV RAX, [0x209E170] = 48 A1 70 9E 09 02 00 00 00 00 (10 bytes)
    # But x64 doesn't normally use absolute addressing

    # Search for the GetLocalPlayer function that might read this global
    print("\n=== Searching for GetLocalPlayer function reading SDK global ===")
    # The function might be: mov rax, [rip+sdk_global]; ret
    # Or: mov rax, [rcx*8 + sdk_global]; ret (for controller index)

    # Look for functions that do MOV RAX, [RIP+disp32] where target is in .data
    # and then RET, and the target global might be the player pointer
    getter_pattern = b'\x48\x8B\x05....\xC3'
    for m in re.finditer(getter_pattern, data):
        pos = m.start()
        if text_raw <= pos < text_raw + text_size:
            disp = struct.unpack('<i', data[pos+3:pos+7])[0]
            target_rva = get_rva_from_offset(data, pos + 7 + disp)
            func_rva = get_rva_from_offset(data, pos)
            if func_rva and target_rva and data_rva <= target_rva < data_rva + data_size:
                # Check if this global is written to anywhere (initialized)
                target_offset = rva_to_offset(data, target_rva)
                if target_offset and target_offset + 8 <= len(data):
                    val = struct.unpack('<Q', data[target_offset:target_offset+8])[0]
                    print(f"  RVA 0x{func_rva:08X}: MOV RAX, [RIP+0x{disp:08X}] -> global 0x{target_rva:08X} = 0x{val:016X}")
                    # Look for code that writes to this global
                    # Search for MOV [RIP+disp32], RAX where target = target_rva
                    write_disp = target_rva - (0x140000000 + pos + 7)  # This is wrong, need proper calc
                    # Actually search for writes to this global
                    for m2 in re.finditer(b'\x48\x89\x05', data):
                        pos2 = m2.start()
                        if text_raw <= pos2 < text_raw + text_size:
                            if pos2 + 7 <= len(data):
                                disp2 = struct.unpack('<i', data[pos2+3:pos2+7])[0]
                                target2_rva = get_rva_from_offset(data, pos2 + 7 + disp2)
                                if target2_rva == target_rva:
                                    func2_rva = get_rva_from_offset(data, pos2)
                                    print(f"    Written by RVA 0x{func2_rva:08X} (file 0x{pos2:08X})")
                                    for instr in disasm_at(data, max(0, pos2-32), 20):
                                        if instr[0] >= pos2-32:
                                            print(f"      0x{instr[0]:08X}: {instr[1]}")

    # 5. Search for functions that take controller index and return player
    print("\n=== Searching for GetLocalPlayer(int controllerIndex) ===")
    # Pattern: cmp rcx, max_players; ja error; mov rax, [rcx*8 + global_array]; ret
    # Or: test ecx, ecx; jl error; mov rax, [rcx*8 + global_array]; ret

    # Search for array access with RCX as index and scale 8
    # SIB byte for [rcx*8 + disp32] = 0xD5 (scale=3, index=1, base=5)
    # Full instruction: 48 8B 04 CD disp32
    array_access = b'\x48\x8B\x04\xCD'
    for m in re.finditer(array_access, data):
        pos = m.start()
        if text_raw <= pos < text_raw + text_size:
            if pos + 7 <= len(data):
                disp = struct.unpack('<i', data[pos+3:pos+7])[0]
                target_rva = get_rva_from_offset(data, pos + 7 + disp)
                func_rva = get_rva_from_offset(data, pos)
                if func_rva:
                    print(f"  RVA 0x{func_rva:08X}: MOV RAX, [RCX*8+0x{disp:X}] -> 0x{target_rva:08X}")
                    for instr in disasm_at(data, max(0, pos-48), 30):
                        if instr[0] >= pos-48:
                            print(f"    0x{instr[0]:08X}: {instr[1]}")

    data.close()

if __name__ == "__main__":
    main()