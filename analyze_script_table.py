#!/usr/bin/env python3
"""
Analyze the script function table and specific candidate functions.
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

def disasm_at(data, offset, max_instructions=30):
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
        # JMP rel32
        elif byte == 0xE9 and pos + 4 < len(data):
            rel = struct.unpack('<i', data[pos+1:pos+5])[0]
            target = pos + 5 + rel
            results.append((pos, f"jmp 0x{target:08X}"))
            pos += 5
        # CMP/JCC patterns
        elif byte == 0x48 and pos + 2 < len(data) and data[pos+1] == 0x83 and data[pos+2] == 0xF9:  # cmp rcx, imm8
            if pos + 3 < len(data):
                imm = data[pos+3]
                results.append((pos, f"cmp rcx, 0x{imm:02X}"))
                pos += 4
        elif byte == 0x85 and pos + 1 < len(data) and data[pos+1] == 0xC9:  # test ecx, ecx
            results.append((pos, "test ecx, ecx"))
            pos += 2
        elif byte == 0x0F and pos + 1 < len(data) and 0x80 <= data[pos+1] <= 0x8F:  # JCC rel32
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
        elif byte >= 0x70 and byte <= 0x7F:  # Short JCC
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

    # 1. Analyze the script function table around "get_local_player"
    print("=== Script Function Table Analysis ===")
    script_table_offset = 0x017B2B28
    print(f"Script table at file offset 0x{script_table_offset:08X}")

    # The table seems to have entries every 16 bytes (string ptr + function ptr + padding?)
    # Let's look at a larger area
    for i in range(-32, 200, 16):
        addr = script_table_offset + i
        if addr + 16 <= len(data):
            # Read two QWORDs
            qword1 = struct.unpack('<Q', data[addr:addr+8])[0]
            qword2 = struct.unpack('<Q', data[addr+8:addr+16])[0]

            # Check if qword1 points to a string in this area
            str_rva = get_rva_from_offset(data, qword1) if qword1 < 0x100000000 else None
            func_rva = get_rva_from_offset(data, qword2) if qword2 < 0x100000000 else None

            # Also check if qword2 is a direct code pointer (high address)
            if qword2 > 0x140000000 and qword2 < 0x142000000:
                func_rva_direct = qword2 - 0x140000000
                if func_rva_direct < 0x02000000:  # within .text
                    func_rva = func_rva_direct

            marker = ""
            if i == 0x40:  # get_local_player string offset
                marker = " <-- get_local_player STRING"
            elif i == 0x80:  # set_max_traffic_cars string offset
                marker = " <-- set_max_traffic_cars STRING"

            if qword1 != 0 or qword2 != 0:
                func_rva_display = func_rva if func_rva else 0
                print(f"  0x{addr:08X}: str_ptr=0x{qword1:016X} func_ptr=0x{qword2:016X} -> func RVA=0x{func_rva_display:08X}{marker}")

    # 2. Disassemble the function at RVA 0x00737E61 (from script table)
    print("\n=== Disassembling function at RVA 0x00737E61 (from script table) ===")
    func_offset = rva_to_offset(data, 0x00737E61)
    if func_offset:
        print(f"Function at file offset 0x{func_offset:08X}")
        for instr in disasm_at(data, func_offset, 40):
            print(f"  0x{instr[0]:08X}: {instr[1]}")

    # 3. Look at the vtable/RTTI areas for SimObjectCharacter
    print("\n=== Analyzing SimObjectCharacter vtable/RTTI areas ===")
    vtable_candidates = [
        0x016E08AE,  # points to code at RVA 0x00007A6F
        0x016E0988,
        0x01752D11,
        0x01752D43,
        0x017B6840,
        0x0204ABE2,  # points to code at RVA 0x00014DC0
        0x0204AC1C,
        0x02088C44,
        0x02088C8D,
        0x0208A4EC,
    ]

    for rva in vtable_candidates:
        offset = rva_to_offset(data, rva)
        if offset:
            print(f"\n  RVA 0x{rva:08X} (file 0x{offset:08X}):")
            # Show surrounding bytes
            for i in range(-32, 64, 16):
                addr = offset + i
                if 0 <= addr < len(data) - 16:
                    hex_bytes = ' '.join(f'{b:02X}' for b in data[addr:addr+16])
                    # Try to interpret as pointers
                    vals = struct.unpack('<QQ', data[addr:addr+16])
                    ptr_info = ""
                    for v in vals:
                        if v > 0x140000000 and v < 0x142000000:
                            code_rva = v - 0x140000000
                            if code_rva < 0x02000000:
                                ptr_info += f" CODE:0x{code_rva:08X}"
                    marker = " <-- STRING REF" if i == 0 else ""
                    print(f"    0x{addr:08X}: {hex_bytes} {ptr_info}{marker}")

    # 4. Search for the actual global player pointer
    # The SDK says it's at RVA 0x209E170 but that's 0 in our binary
    # Let's search for a global that points to a SimObjectCharacter
    # by looking at the vtable pointer in the heap

    # 5. Look at the function at RVA 0x00007A6F and 0x00014DC0 (from vtable refs)
    print("\n=== Disassembling vtable-referenced functions ===")
    for rva in [0x00007A6F, 0x00014DC0]:
        offset = rva_to_offset(data, rva)
        if offset:
            print(f"\n  Function at RVA 0x{rva:08X} (file 0x{offset:08X}):")
            for instr in disasm_at(data, offset, 30):
                print(f"    0x{instr[0]:08X}: {instr[1]}")

    data.close()

if __name__ == "__main__":
    main()