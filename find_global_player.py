#!/usr/bin/env python3
"""
Find global player pointer in .data section.
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

    print(f".text: RVA 0x{text_rva:08X}-0x{text_rva+text_size:08X}")
    print(f".data: RVA 0x{data_rva:08X}-0x{data_rva+data_size:08X}")
    print(f".rdata: RVA 0x{rdata_rva:08X}-0x{rdata_rva+rdata_size:08X}")

    # 1. Find SimObjectCharacter vtable
    # Search for RTTI "?AVSimObjectCharacter@UFG@@" and find vtable before it
    print("\n=== Finding SimObjectCharacter vtable ===")
    simobj_vtable_rva = None
    for m in re.finditer(b'\?AVSimObjectCharacter@UFG@@', data):
        pos = m.start()
        rva = get_rva_from_offset(data, pos)
        if rva and rdata_rva <= rva < rdata_rva + rdata_size:
            print(f"  Found RTTI at RVA 0x{rva:08X} (file 0x{pos:08X})")
            # Look for vtable before RTTI (typically at offset -8 or -16)
            for i in range(-64, 0, 8):
                addr = pos + i
                if 0 <= addr < len(data) - 8:
                    val = struct.unpack('<Q', data[addr:addr+8])[0]
                    if val > 0x140000000 and val < 0x142000000:
                        code_rva = val - 0x140000000
                        if text_rva <= code_rva < text_rva + text_size:
                            # Verify it's a vtable (multiple consecutive code pointers)
                            is_vtable = True
                            for j in range(1, 10):
                                addr2 = addr + j * 8
                                if addr2 + 8 <= len(data):
                                    val2 = struct.unpack('<Q', data[addr2:addr2+8])[0]
                                    if not (val2 > 0x140000000 and val2 < 0x142000000):
                                        is_vtable = False
                                        break
                            if is_vtable:
                                simobj_vtable_rva = code_rva
                                print(f"    Found vtable at RVA 0x{code_rva:08X} (offset {i})")
                                break
            if simobj_vtable_rva:
                break

    if not simobj_vtable_rva:
        print("  Could not find vtable via RTTI, searching .rdata for vtable pattern...")
        # Search .rdata for vtable pattern (array of code pointers)
        for addr in range(rdata_raw, rdata_raw + rdata_size - 80, 8):
            if addr + 80 <= len(data):
                # Check if this looks like a vtable (10+ consecutive code pointers)
                is_vtable = True
                for j in range(10):
                    if addr + j * 8 + 8 > len(data):
                        is_vtable = False
                        break
                    val = struct.unpack('<Q', data[addr + j * 8:addr + j * 8 + 8])[0]
                    if not (val > 0x140000000 and val < 0x142000000):
                        is_vtable = False
                        break
                if is_vtable:
                    code_rva = struct.unpack('<Q', data[addr:addr+8])[0] - 0x140000000
                    if text_rva <= code_rva < text_rva + text_size:
                        # Check if near SimObjectCharacter RTTI
                        rva = get_rva_from_offset(data, addr)
                        print(f"  Candidate vtable at RVA 0x{rva:08X} (first entry -> 0x{code_rva:08X})")

    # 2. Search .data for global player pointer
    print("\n\n=== Searching .data for global player pointer ===")
    # The player object would be in heap, but there might be a global pointer to it
    # Or the player object itself might be a global (less likely)

    # Check the SDK's claimed RVA 0x209E170
    sdk_rva = 0x209E170
    sdk_offset = rva_to_offset(data, sdk_rva)
    if sdk_offset:
        val = struct.unpack('<Q', data[sdk_offset:sdk_offset+8])[0]
        print(f"  SDK RVA 0x{sdk_rva:08X} (file 0x{sdk_offset:08X}) = 0x{val:016X}")

    # Search for globals that look like pointers to heap objects
    # Heap addresses are typically > 0x142000000 and not in module range
    print(f"\n  Scanning .data for heap pointers...")
    heap_pointers = []
    for addr in range(data_raw, data_raw + data_size, 8):
        if addr + 8 <= len(data):
            val = struct.unpack('<Q', data[addr:addr+8])[0]
            if val > 0x142000000 and val < 0x7FFFFFFFFFFF:
                rva = get_rva_from_offset(data, addr)
                heap_pointers.append((rva, addr, val))

    print(f"  Found {len(heap_pointers)} heap pointers in .data")

    # For each heap pointer, check if there's code that writes to it with a SimObjectCharacter
    # Look for MOV [RIP+disp32], RAX where target is this global
    if simobj_vtable_rva:
        simobj_vtable_va = 0x140000000 + simobj_vtable_rva
        print(f"\n  SimObjectCharacter vtable VA: 0x{simobj_vtable_va:016X}")

        # Search for code that writes the vtable to an object
        # MOV [RAX], RDX where RDX = vtable (or similar)
        # Or MOV [RIP+disp32], RAX where RAX = vtable
        mov_vtable = b'\x48\x89\x10'  # mov [rax], rdx
        for m in re.finditer(mov_vtable, data):
            pos = m.start()
            if text_raw <= pos < text_raw + text_size:
                func_rva = get_rva_from_offset(data, pos)
                if func_rva:
                    print(f"    MOV [RAX], RDX at RVA 0x{func_rva:08X}")
                    for instr in disasm_at(data, max(0, pos-32), 20):
                        if instr[0] >= pos-32:
                            print(f"      0x{instr[0]:08X}: {instr[1]}")

    # 3. Search for GetLocalPlayer function pattern
    # Function that takes int controllerIndex and returns SimObjectCharacter*
    # In x64: RCX = controllerIndex, RAX = return value
    # Typical pattern: test ecx, ecx; jl/jle error; mov rax, [global_player_array + rcx*8]; ret

    print("\n\n=== Searching for GetLocalPlayer function pattern ===")
    # Look for: test ecx, ecx followed by conditional jump and array access
    test_ecx = b'\x85\xC9'
    candidates = []
    for m in re.finditer(test_ecx, data):
        pos = m.start()
        if text_raw <= pos < text_raw + text_size:
            # Look ahead for conditional jump within 16 bytes
            ahead = data[pos:pos+48]
            has_jcc = False
            for jcc in [b'\x0F\x8C', b'\x0F\x8E', b'\x0F\x86', b'\x0F\x82',  # jl, jle, jbe, jb
                       b'\x7C', b'\x7E', b'\x76', b'\x72']:  # short jl, jle, jbe, jb
                if ahead.find(jcc) >= 0 and ahead.find(jcc) < 16:
                    has_jcc = True
                    break

            if has_jcc:
                # Look for array access with RCX
                # mov rax, [rcx*8 + disp32] = 48 8B 04 CD disp32
                # mov rax, [rax + rcx*8] = 48 8B 04 C8
                # mov rax, [rcx + disp32] = 48 8B 81 disp32
                func_rva = get_rva_from_offset(data, pos)
                if func_rva:
                    # Disassemble to verify
                    instrs = disasm_at(data, pos, 20)
                    has_array = False
                    has_ret = False
                    for instr in instrs:
                        if 'rcx' in instr[1].lower() and ('[' in instr[1] or 'mov rax' in instr[1].lower()):
                            has_array = True
                        if 'ret' in instr[1].lower():
                            has_ret = True
                    if has_array and has_ret:
                        candidates.append((func_rva, pos, instrs))

    print(f"  Found {len(candidates)} candidates")
    for func_rva, pos, instrs in candidates[:10]:
        print(f"\n  Candidate at RVA 0x{func_rva:08X} (file 0x{pos:08X}):")
        for instr in instrs:
            print(f"    0x{instr[0]:08X}: {instr[1]}")

    # 4. Search for simple getter returning global player pointer
    # MOV RAX, [RIP+disp32]; RET where target is a global pointer to player
    print("\n\n=== Simple global getters returning player pointer ===")
    getter_pattern = b'\x48\x8B\x05....\xC3'
    for m in re.finditer(getter_pattern, data):
        pos = m.start()
        if text_raw <= pos < text_raw + text_size:
            disp = struct.unpack('<i', data[pos+3:pos+7])[0]
            target_rva = get_rva_from_offset(data, pos + 7 + disp)
            func_rva = get_rva_from_offset(data, pos)
            if func_rva and target_rva and data_rva <= target_rva < data_rva + data_size:
                # Check what's at the target global
                target_offset = rva_to_offset(data, target_rva)
                if target_offset and target_offset + 8 <= len(data):
                    val = struct.unpack('<Q', data[target_offset:target_offset+8])[0]
                    if val > 0x142000000 and val < 0x7FFFFFFFFFFF:
                        print(f"  RVA 0x{func_rva:08X}: MOV RAX, [RIP+0x{disp:08X}] -> global 0x{target_rva:08X} = 0x{val:016X} (HEAP POINTER!)")
                        # This is a strong candidate!

    data.close()

if __name__ == "__main__":
    main()