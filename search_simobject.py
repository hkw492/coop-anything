#!/usr/bin/env python3
"""
Search for SimObjectCharacter broadly and analyze GameState vtable functions.
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

    # 1. Search for SimObjectCharacter broadly
    print("=== Searching for SimObjectCharacter ===")
    for m in re.finditer(b'SimObjectCharacter', data):
        pos = m.start()
        rva = get_rva_from_offset(data, pos)
        if rva:
            print(f"  RVA 0x{rva:08X} (file 0x{pos:08X})")
            # Show context
            context = data[max(0,pos-32):pos+64]
            clean = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in context)
            print(f"    ...{clean}...")

    # 2. Search for RTTI pattern for SimObjectCharacter
    print("\n=== Searching for SimObjectCharacter RTTI patterns ===")
    for pattern in [b'SimObjectCharacter', b'?AVSimObjectCharacter'.replace(b'?', b'\\?'), b'SimObject', b'ObjectCharacter']:
        for m in re.finditer(pattern, data):
            pos = m.start()
            rva = get_rva_from_offset(data, pos)
            if rva and rdata_rva <= rva < rdata_rva + rdata_size:
                print(f"  RTTI? at RVA 0x{rva:08X} (file 0x{pos:08X}) in .rdata")
                # Look at surrounding for vtable
                for i in range(-64, 64, 8):
                    addr = pos + i
                    if 0 <= addr < len(data) - 8:
                        val = struct.unpack('<Q', data[addr:addr+8])[0]
                        if val > 0x140000000 and val < 0x142000000:
                            code_rva = val - 0x140000000
                            if text_rva <= code_rva < text_rva + text_size:
                                print(f"    Vtable entry at offset {i:+d} -> CODE RVA 0x{code_rva:08X}")

    # 3. Analyze GameState vtable functions with actual code
    print("\n\n=== Analyzing GameState vtable functions ===")
    vtable_rva = 0x01784BD0
    vtable_offset = rva_to_offset(data, vtable_rva)
    if vtable_offset:
        for i in range(64):
            addr = vtable_offset + i * 8
            if addr + 8 <= len(data):
                val = struct.unpack('<Q', data[addr:addr+8])[0]
                if val != 0 and val > 0x140000000 and val < 0x142000000:
                    code_rva = val - 0x140000000
                    if text_rva <= code_rva < text_rva + text_size:
                        func_offset = rva_to_offset(data, code_rva)
                        if func_offset:
                            # Check if function has more than just RET
                            instrs = disasm_at(data, func_offset, 30)
                            if len(instrs) > 2 or (len(instrs) > 0 and instrs[0][1] != 'ret'):
                                print(f"\n  [{i}] Vtable entry -> RVA 0x{code_rva:08X}:")
                                for instr in instrs:
                                    print(f"    0x{instr[0]:08X}: {instr[1]}")

    # 4. Search for "GetLocalPlayer" in the binary
    print("\n\n=== Searching for GetLocalPlayer function ===")
    for pattern in [b'GetLocalPlayer', b'get_local_player', b'LocalPlayer', b'localPlayer']:
        for m in re.finditer(pattern, data):
            pos = m.start()
            rva = get_rva_from_offset(data, pos)
            if rva:
                # Check if it's in .rdata (string) or .text (code)
                if rdata_rva <= rva < rdata_rva + rdata_size:
                    print(f"  String '{pattern.decode()}' at RVA 0x{rva:08X} (file 0x{pos:08X})")
                elif text_rva <= rva < text_rva + text_size:
                    print(f"  CODE '{pattern.decode()}' at RVA 0x{rva:08X} (file 0x{pos:08X})")
                    # Try to find function
                    for i in range(-64, 64, 8):
                        addr = pos + i
                        if 0 <= addr < len(data) - 8:
                            val = struct.unpack('<Q', data[addr:addr+8])[0]
                            if val > 0x140000000 and val < 0x142000000:
                                code_rva = val - 0x140000000
                                if text_rva <= code_rva < text_rva + text_size:
                                    print(f"    Nearby code ptr at 0x{addr:08X} -> RVA 0x{code_rva:08X}")

    # 5. Search for player controller / player manager
    print("\n\n=== Searching for PlayerController / PlayerManager ===")
    for pattern in [b'PlayerController', b'player_controller', b'PlayerManager', b'player_manager',
                    b'PlayerInfo', b'player_info', b'PlayerData', b'player_data']:
        for m in re.finditer(pattern, data):
            pos = m.start()
            rva = get_rva_from_offset(data, pos)
            if rva:
                print(f"  '{pattern.decode()}' at RVA 0x{rva:08X} (file 0x{pos:08X})")

    # 6. Search for "m_pLocalPlayer" or "m_localPlayer" member
    print("\n\n=== Searching for m_pLocalPlayer / m_localPlayer ===")
    for pattern in [b'm_pLocalPlayer', b'm_localPlayer', b'm_LocalPlayer', b'mpLocalPlayer']:
        for m in re.finditer(pattern, data):
            pos = m.start()
            rva = get_rva_from_offset(data, pos)
            if rva:
                print(f"  '{pattern.decode()}' at RVA 0x{rva:08X} (file 0x{pos:08X})")

    data.close()

if __name__ == "__main__":
    main()