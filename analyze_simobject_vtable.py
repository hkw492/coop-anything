#!/usr/bin/env python3
"""
Analyze SimObjectCharacter vtable and find global player pointer.
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

    # 1. Analyze the SimObjectCharacter RTTI at RVA 0x0208A4EC
    print("=== SimObjectCharacter RTTI at RVA 0x0208A4EC ===")
    rtti_rva = 0x0208A4EC
    rtti_offset = rva_to_offset(data, rtti_rva)
    if rtti_offset:
        print(f"RTTI at file offset 0x{rtti_offset:08X}")
        # Show surrounding area
        for i in range(-128, 128, 8):
            addr = rtti_offset + i
            if 0 <= addr < len(data) - 8:
                val = struct.unpack('<Q', data[addr:addr+8])[0]
                if val != 0:
                    if val > 0x140000000 and val < 0x142000000:
                        code_rva = val - 0x140000000
                        if text_rva <= code_rva < text_rva + text_size:
                            print(f"  Offset {i:+4d}: 0x{addr:08X} -> CODE RVA 0x{code_rva:08X}")
                            func_offset = rva_to_offset(data, code_rva)
                            if func_offset:
                                for instr in disasm_at(data, func_offset, 10):
                                    print(f"           0x{instr[0]:08X}: {instr[1]}")
                    elif rdata_rva <= val < rdata_rva + rdata_size:
                        print(f"  Offset {i:+4d}: 0x{addr:08X} -> RDATA 0x{val:016X}")
                    elif data_rva <= val < data_rva + data_size:
                        print(f"  Offset {i:+4d}: 0x{addr:08X} -> DATA 0x{val:016X}")
                    else:
                        print(f"  Offset {i:+4d}: 0x{addr:08X} -> 0x{val:016X}")

    # 2. Look at the RTTI at RVA 0x01676C10 which had vtable entries
    print("\n\n=== RTTI at RVA 0x01676C10 (with vtable entries) ===")
    rtti_rva2 = 0x01676C10
    rtti_offset2 = rva_to_offset(data, rtti_rva2)
    if rtti_offset2:
        print(f"RTTI at file offset 0x{rtti_offset2:08X}")
        for i in range(-128, 128, 8):
            addr = rtti_offset2 + i
            if 0 <= addr < len(data) - 8:
                val = struct.unpack('<Q', data[addr:addr+8])[0]
                if val != 0:
                    if val > 0x140000000 and val < 0x142000000:
                        code_rva = val - 0x140000000
                        if text_rva <= code_rva < text_rva + text_size:
                            print(f"  Offset {i:+4d}: 0x{addr:08X} -> CODE RVA 0x{code_rva:08X}")
                            func_offset = rva_to_offset(data, code_rva)
                            if func_offset:
                                for instr in disasm_at(data, func_offset, 10):
                                    print(f"           0x{instr[0]:08X}: {instr[1]}")

    # 3. Search .data for global pointer to SimObjectCharacter vtable
    # First, find the SimObjectCharacter vtable address
    print("\n\n=== Searching .data for global player pointer ===")
    # The vtable for SimObjectCharacter should be in .rdata
    # Let's find it by looking at the RTTI structure
    # RTTI typically has: [0] = vtable pointer, [1] = type name, [2] = base class array, etc.

    # Search for the vtable pointer in .rdata near the SimObjectCharacter RTTI
    simobj_vtable_rva = None
    for rva in [0x0208A4EC, 0x01676C10, 0x016CC520, 0x0177FD88, 0x017BD0F0, 0x017F6A48]:
        offset = rva_to_offset(data, rva)
        if offset:
            # Check before the RTTI for vtable pointer
            for i in range(-64, 0, 8):
                addr = offset + i
                if 0 <= addr < len(data) - 8:
                    val = struct.unpack('<Q', data[addr:addr+8])[0]
                    if val > 0x140000000 and val < 0x142000000:
                        code_rva = val - 0x140000000
                        if text_rva <= code_rva < text_rva + text_size:
                            # Check if this looks like a vtable (multiple code pointers in a row)
                            is_vtable = True
                            for j in range(1, 8):
                                addr2 = addr + j * 8
                                if addr2 + 8 <= len(data):
                                    val2 = struct.unpack('<Q', data[addr2:addr2+8])[0]
                                    if not (val2 > 0x140000000 and val2 < 0x142000000):
                                        is_vtable = False
                                        break
                            if is_vtable:
                                simobj_vtable_rva = code_rva
                                print(f"  Found SimObjectCharacter vtable at RVA 0x{code_rva:08X} (from RTTI at 0x{rva:08X})")
                                break
            if simobj_vtable_rva:
                break

    if simobj_vtable_rva:
        simobj_vtable_va = 0x140000000 + simobj_vtable_rva
        print(f"\n  SimObjectCharacter vtable VA: 0x{simobj_vtable_va:016X}")

        # Search .data for pointers to this vtable (i.e., SimObjectCharacter instances)
        print(f"\n  Searching .data for pointers to vtable...")
        for addr in range(data_raw, data_raw + data_size, 8):
            if addr + 8 <= len(data):
                val = struct.unpack('<Q', data[addr:addr+8])[0]
                if val == simobj_vtable_va:
                    rva = get_rva_from_offset(data, addr)
                    print(f"    FOUND! Global at RVA 0x{rva:08X} (file 0x{addr:08X}) points to SimObjectCharacter vtable")
                    # This global IS a SimObjectCharacter* (the player object)

        # Also search for globals that point to an object THAT has this vtable
        # i.e., global -> SimObjectCharacter* -> vtable
        print(f"\n  Searching .data for pointer to SimObjectCharacter instance...")
        for addr in range(data_raw, data_raw + data_size, 8):
            if addr + 8 <= len(data):
                val = struct.unpack('<Q', data[addr:addr+8])[0]
                # Check if this points to a valid heap address (not in module)
                if val > 0x142000000 and val < 0x7FFFFFFFFFFF:
                    # Could be a heap pointer. Check if the heap object has our vtable
                    # We can't dereference, but we can look for code that writes this global
                    rva = get_rva_from_offset(data, addr)
                    print(f"    Candidate global at RVA 0x{rva:08X} (file 0x{addr:08X}) = 0x{val:016X} (heap pointer?)")

    # 4. Disassemble GameState vtable functions that might be GetLocalPlayer
    print("\n\n=== GameState vtable candidate functions ===")
    candidates = [
        (2, 0x00411A70),
        (3, 0x00411670),
        (5, 0x00412490),
        (6, 0x00411060),
        (32, 0x00411A40),
        (36, 0x00410FE0),
        (49, 0x00411880),
        (50, 0x00410EE0),
        (51, 0x00413620),
    ]

    for idx, rva in candidates:
        offset = rva_to_offset(data, rva)
        if offset:
            print(f"\n  [{idx}] RVA 0x{rva:08X}:")
            for instr in disasm_at(data, offset, 40):
                print(f"    0x{instr[0]:08X}: {instr[1]}")

    data.close()

if __name__ == "__main__":
    main()