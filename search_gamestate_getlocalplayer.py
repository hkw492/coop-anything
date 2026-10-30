#!/usr/bin/env python3
"""
Search for UFG::GameState::GetLocalPlayer and analyze script function table structure.
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

def disasm_at(data, offset, max_instructions=60):
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

    # 1. Search for UFG::GameState or GameState in symbols
    print("=== Searching for UFG::GameState / GameState symbols ===")
    for pattern in [b'UFG::GameState', b'GameState', b'UFG::GameState::GetLocalPlayer',
                    b'GetLocalPlayer', b'getLocalPlayer', b'LocalPlayer']:
        for m in re.finditer(pattern, data):
            pos = m.start()
            rva = get_rva_from_offset(data, pos)
            if rva:
                print(f"  '{pattern.decode()}' at RVA 0x{rva:08X} (file 0x{pos:08X})")

    # 2. Analyze the script function table more carefully
    print("\n=== Detailed script function table analysis ===")
    script_table_offset = 0x017B2B28
    print(f"Script table at file offset 0x{script_table_offset:08X}")

    # Look at a larger area around the table
    for i in range(-128, 256, 8):
        addr = script_table_offset + i
        if 0 <= addr < len(data) - 8:
            val = struct.unpack('<Q', data[addr:addr+8])[0]
            if val != 0:
                # Check if it's a string in this area
                if addr >= script_table_offset and addr < script_table_offset + 512:
                    # Try to read as string
                    s = data[addr:addr+64].split(b'\0')[0]
                    if len(s) > 4 and all(32 <= b <= 126 for b in s):
                        print(f"  0x{addr:08X}: STRING '{s.decode()}'")
                # Check if it points to code
                if val > 0x140000000 and val < 0x142000000:
                    code_rva = val - 0x140000000
                    if text_rva <= code_rva < text_rva + text_size:
                        print(f"  0x{addr:08X}: CODE PTR -> RVA 0x{code_rva:08X}")
                        func_offset = rva_to_offset(data, code_rva)
                        if func_offset:
                            for instr in disasm_at(data, func_offset, 15):
                                print(f"    0x{instr[0]:08X}: {instr[1]}")
                # Check if it points to data
                elif data_rva <= val < data_rva + data_size:
                    print(f"  0x{addr:08X}: DATA PTR -> 0x{val:016X}")
                elif rdata_rva <= val < rdata_rva + rdata_size:
                    print(f"  0x{addr:08X}: RDATA PTR -> 0x{val:016X}")

    # 3. Look at the "LocalPlayer" string at RVA 0x0176D008
    print("\n=== Analyzing 'LocalPlayer' string at RVA 0x0176D008 ===")
    lp_offset = rva_to_offset(data, 0x0176D008)
    if lp_offset:
        print(f"String at file offset 0x{lp_offset:08X}")
        for i in range(-128, 128, 16):
            addr = lp_offset + i
            if 0 <= addr < len(data) - 16:
                hex_bytes = ' '.join(f'{b:02X}' for b in data[addr:addr+16])
                ascii_bytes = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data[addr:addr+16])
                marker = " <-- STRING" if i == 0 else ""
                print(f"  0x{addr:08X}: {hex_bytes:<48} {ascii_bytes}{marker}")

    # 4. Search for cross-references to the LocalPlayer string
    print("\n=== Searching for references to LocalPlayer string ===")
    lp_rva = 0x0176D008
    # Search for RIP-relative LEA/MOV to this address
    # The VA would be image_base + lp_rva
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    image_base = struct.unpack('<Q', data[pe_offset+30:pe_offset+38])[0]
    lp_va = image_base + lp_rva

    # Search for LEA RAX, [RIP+disp32] where target is near lp_va
    lea_pattern = b'\x48\x8D\x05'
    for m in re.finditer(lea_pattern, data):
        pos = m.start()
        if pos + 7 <= len(data):
            disp = struct.unpack('<i', data[pos+3:pos+7])[0]
            target_va = (pos + 7) + disp + image_base  # approximate
            if abs(target_va - lp_va) < 0x1000:
                func_rva = get_rva_from_offset(data, pos)
                if func_rva:
                    print(f"  0x{pos:08X} (RVA 0x{func_rva:08X}): LEA RAX, [RIP+0x{disp:08X}] -> VA 0x{target_va:016X} (near LocalPlayer!)")
                    for instr in disasm_at(data, pos-16 if pos>=16 else 0, 20):
                        if instr[0] >= pos-16:
                            print(f"    0x{instr[0]:08X}: {instr[1]}")

    # 5. Search for functions named GetLocalPlayer in the binary
    print("\n=== Searching for GetLocalPlayer function name ===")
    for m in re.finditer(b'GetLocalPlayer', data):
        pos = m.start()
        rva = get_rva_from_offset(data, pos)
        if rva:
            print(f"  At RVA 0x{rva:08X} (file 0x{pos:08X})")
            # Look at surrounding area for function
            for i in range(-64, 64, 8):
                addr = pos + i
                if 0 <= addr < len(data) - 8:
                    val = struct.unpack('<Q', data[addr:addr+8])[0]
                    if val > 0x140000000 and val < 0x142000000:
                        code_rva = val - 0x140000000
                        if text_rva <= code_rva < text_rva + text_size:
                            print(f"    Nearby code ptr at 0x{addr:08X} -> RVA 0x{code_rva:08X}")

    data.close()

if __name__ == "__main__":
    main()