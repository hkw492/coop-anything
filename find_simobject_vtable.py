#!/usr/bin/env python3
"""
Find SimObjectCharacter vtable and global player pointer.
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

    # 1. Find SimObjectCharacter RTTI and vtable
    print("=== Finding SimObjectCharacter vtable ===")
    for m in re.finditer(b'\.\\?AVSimObjectCharacter@@', data):
        pos = m.start()
        rva = get_rva_from_offset(data, pos)
        if rva:
            print(f"\nRTTI at RVA 0x{rva:08X} (file 0x{pos:08X})")
            # vtable typically has RTTI pointer at offset -8 from first virtual function
            # But RTTI structure itself has vtable pointer at offset +8 or similar
            # Let's search for vtable pointers near this RTTI
            for i in range(-256, 256, 8):
                addr = pos + i
                if 0 <= addr < len(data) - 8:
                    val = struct.unpack('<Q', data[addr:addr+8])[0]
                    if val > 0x140000000 and val < 0x142000000:
                        code_rva = val - 0x140000000
                        if text_rva <= code_rva < text_rva + text_size:
                            print(f"  Vtable entry at 0x{addr:08X} (offset {i:+d}) -> CODE RVA 0x{code_rva:08X}")
                            func_offset = rva_to_offset(data, code_rva)
                            if func_offset:
                                for instr in disasm_at(data, func_offset, 10):
                                    print(f"    0x{instr[0]:08X}: {instr[1]}")

    # 2. Search for global pointer to SimObjectCharacter (player pointer)
    # Look for globals in .data that point to vtable addresses
    print("\n\n=== Searching .data for SimObjectCharacter instance pointers ===")
    # First, let's find the SimObjectCharacter vtable address
    simobj_vtable_rva = None
    for m in re.finditer(b'\.\\?AVSimObjectCharacter@@', data):
        pos = m.start()
        rva = get_rva_from_offset(data, pos)
        if rva:
            # Look for vtable before RTTI
            for i in range(-128, 0, 8):
                addr = pos + i
                if 0 <= addr < len(data) - 8:
                    val = struct.unpack('<Q', data[addr:addr+8])[0]
                    if val > 0x140000000 and val < 0x142000000:
                        code_rva = val - 0x140000000
                        if text_rva <= code_rva < text_rva + text_size:
                            simobj_vtable_rva = code_rva
                            print(f"  SimObjectCharacter vtable at RVA 0x{code_rva:08X} (from RTTI at 0x{rva:08X})")
                            break
            if simobj_vtable_rva:
                break

    if simobj_vtable_rva:
        simobj_vtable_va = 0x140000000 + simobj_vtable_rva
        print(f"\n  SimObjectCharacter vtable VA: 0x{simobj_vtable_va:016X}")

        # Search .data for pointers to this vtable
        print(f"\n  Searching .data (RVA 0x{data_rva:08X}-0x{data_rva+data_size:08X}) for vtable pointer...")
        for addr in range(data_raw, data_raw + data_size, 8):
            if addr + 8 <= len(data):
                val = struct.unpack('<Q', data[addr:addr+8])[0]
                if val == simobj_vtable_va:
                    rva = get_rva_from_offset(data, addr)
                    print(f"    FOUND! Global at RVA 0x{rva:08X} (file 0x{addr:08X}) points to SimObjectCharacter vtable")
                    # Disassemble code that writes to this global
                    # Search for MOV [RIP+disp32], RAX where target is this global
                    target_disp = rva - 0x140000000  # This is the RVA of the global
                    # Actually we need to find code that writes to this global

    # 3. Search for functions that return SimObjectCharacter* by looking for
    # functions that load the vtable into RAX before returning
    print("\n\n=== Searching for functions returning SimObjectCharacter* ===")
    if simobj_vtable_rva:
        simobj_vtable_va = 0x140000000 + simobj_vtable_rva
        # Look for LEA RAX, [RIP+disp32] where target is the vtable
        lea_pattern = b'\x48\x8D\x05'
        for m in re.finditer(lea_pattern, data):
            pos = m.start()
            if text_raw <= pos < text_raw + text_size:
                disp = struct.unpack('<i', data[pos+3:pos+7])[0]
                target_va = (pos + 7) + disp + 0x140000000  # approximate
                if target_va == simobj_vtable_va:
                    func_rva = get_rva_from_offset(data, pos)
                    if func_rva:
                        print(f"  RVA 0x{func_rva:08X}: LEA RAX, [RIP+0x{disp:08X}] -> SimObjectCharacter vtable!")
                        for instr in disasm_at(data, max(0, pos-32), 30):
                            if instr[0] >= pos-32:
                                print(f"    0x{instr[0]:08X}: {instr[1]}")

    # 4. Search for the global player pointer directly
    # The SDK said it's at RVA 0x209E170 but that's NULL
    # Let's search for a global in .data that gets initialized to a player
    print("\n\n=== Searching for global player pointer in .data ===")
    # Look at the .data section for pointers that might be the player
    # The player object would have the SimObjectCharacter vtable as its first qword
    if simobj_vtable_rva:
        simobj_vtable_va = 0x140000000 + simobj_vtable_rva
        print(f"  Looking for heap objects with vtable 0x{simobj_vtable_va:016X}")
        # This would be in heap, not in .data. But there might be a global pointer TO the heap object.
        # Search .data for a pointer that, when dereferenced, points to the vtable
        for addr in range(data_raw, data_raw + data_size, 8):
            if addr + 8 <= len(data):
                val = struct.unpack('<Q', data[addr:addr+8])[0]
                # Check if this points to a valid heap address (not in module range)
                if val > 0x142000000 and val < 0x7FFFFFFFFFFF:
                    # This could be a heap pointer. Check if it points to the vtable
                    # We can't dereference heap from static analysis, but we can check if
                    # there's code that writes this global with a SimObjectCharacter*
                    pass

    # 5. Look at the functions around the "LocalPlayerIsInCombatManager" references
    print("\n\n=== Analyzing functions referencing LocalPlayerIsInCombatManager ===")
    refs = [
        0x0032E7FA, 0x00335A10, 0x00336E34, 0x0033D1BD, 0x0033D8AD,
        0x0035025D, 0x00350314, 0x00350694, 0x003506AF, 0x00350709,
        0x00350755, 0x0035124C, 0x003513E5, 0x00357A65, 0x0036145D,
        0x0037DA33, 0x0037ECA4, 0x003996F0, 0x0039A230, 0x0039AA80,
    ]
    for rva in refs:
        offset = rva_to_offset(data, rva)
        if offset:
            # Find function start
            start = offset
            for back in range(offset, max(text_raw, offset-200), -1):
                if back >= 3 and data[back:back+3] in [b'\x48\x89\x5C', b'\x48\x89\x74', b'\x48\x89\x7C']:
                    start = back
                    break
                if back >= 1 and data[back] == 0x55:
                    start = back
                    break
            print(f"\n  Function at RVA 0x{rva:08X} (starts ~0x{get_rva_from_offset(data, start):08X}):")
            for instr in disasm_at(data, start, 30):
                print(f"    0x{instr[0]:08X}: {instr[1]}")

    data.close()

if __name__ == "__main__":
    main()