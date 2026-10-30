#!/usr/bin/env python3
"""
Search for Simulation class, GetSimObject, GetInstance, and player-related strings in sdhdship.exe
"""

import mmap
import struct
import re
from pathlib import Path

EXE_PATH = Path(r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe")

def read_exe():
    with open(EXE_PATH, "rb") as f:
        return mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

def get_section_info(data):
    if data[:2] != b'MZ':
        return None
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    if pe_offset + 4 > len(data) or data[pe_offset:pe_offset+4] != b'PE\0\0':
        return None
    num_sections = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
    opt_header_size = struct.unpack('<H', data[pe_offset+20:pe_offset+22])[0]
    sections_start = pe_offset + 24 + opt_header_size

    sections = {}
    for i in range(num_sections):
        sec = sections_start + i * 40
        if sec + 40 > len(data):
            break
        name = data[sec:sec+8].rstrip(b'\0').decode('ascii', errors='ignore')
        sec_rva = struct.unpack('<I', data[sec+12:sec+16])[0]
        sec_size = struct.unpack('<I', data[sec+16:sec+20])[0]
        sec_raw = struct.unpack('<I', data[sec+20:sec+24])[0]
        sections[name] = {'rva': sec_rva, 'size': sec_size, 'raw': sec_raw}
    return sections

def rva_to_offset(sections, rva):
    for name, sec in sections.items():
        if sec['rva'] <= rva < sec['rva'] + sec['size']:
            return sec['raw'] + (rva - sec['rva'])
    return None

def get_rva_from_offset(sections, offset):
    for name, sec in sections.items():
        if sec['raw'] <= offset < sec['raw'] + sec['size']:
            return sec['rva'] + (offset - sec['raw'])
    return None

def search_strings(data, patterns):
    """Search for byte patterns in data"""
    results = {}
    for pattern in patterns:
        results[pattern] = []
        for m in re.finditer(re.escape(pattern), data):
            pos = m.start()
            rva = get_rva_from_offset(sections, pos)
            if rva:
                results[pattern].append((rva, pos))
    return results

def disasm_function(data, sections, func_rva, max_instructions=50):
    """Disassemble a function starting at func_rva"""
    offset = rva_to_offset(sections, func_rva)
    if not offset:
        return []

    results = []
    p = offset
    text = sections.get('.text', {})
    text_end = text.get('raw', 0) + text.get('size', 0)

    for _ in range(max_instructions):
        if p >= len(data) or p >= text_end:
            break
        byte = data[p]
        rva = get_rva_from_offset(sections, p)

        if byte == 0xC3:
            results.append((rva, "ret"))
            break
        elif byte == 0xC2 and p + 2 < len(data):
            imm = struct.unpack('<H', data[p+1:p+3])[0]
            results.append((rva, f"ret 0x{imm:04X}"))
            break
        elif byte == 0xE8 and p + 4 < len(data):
            rel = struct.unpack('<i', data[p+1:p+5])[0]
            target = p + 5 + rel
            target_rva = get_rva_from_offset(sections, target)
            results.append((rva, f"call 0x{target_rva:08X}"))
            p += 5
        elif byte == 0xFF and p + 1 < len(data) and data[p+1] == 0x15:
            if p + 5 < len(data):
                disp = struct.unpack('<i', data[p+2:p+6])[0]
                target = p + 6 + disp
                target_rva = get_rva_from_offset(sections, target)
                results.append((rva, f"call [rip+0x{disp:08X}] -> 0x{target_rva:08X}"))
                p += 6
        elif byte == 0x48 and p + 1 < len(data) and data[p+1] == 0x8B:
            if p + 6 < len(data) and data[p+2] == 0x05:
                disp = struct.unpack('<i', data[p+3:p+7])[0]
                target = p + 7 + disp
                target_rva = get_rva_from_offset(sections, target)
                results.append((rva, f"mov rax, [rip+0x{disp:08X}] -> 0x{target_rva:08X}"))
                p += 7
            elif p + 3 < len(data):
                modrm = data[p+2]
                if (modrm & 0xC7) == 0x04:  # SIB
                    if p + 7 < len(data):
                        sib = data[p+3]
                        disp = struct.unpack('<i', data[p+4:p+8])[0]
                        index = (sib >> 3) & 0x7
                        scale = (sib >> 6) & 0x3
                        scale_val = 1 << scale
                        regs = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi']
                        index_str = f'{regs[index]}*{scale_val}' if index != 4 else ''
                        base_str = regs[sib & 0x7]
                        if (sib & 0x7) == 5 and (modrm >> 6) == 0:
                            addr = f'[rip+{index_str}+0x{disp:X}]' if index_str else f'[rip+0x{disp:X}]'
                        else:
                            addr = f'[{base_str}+{index_str}+0x{disp:X}]' if index_str else f'[{base_str}+0x{disp:X}]'
                        results.append((rva, f"mov rax, {addr}"))
                        p += 8
                    else:
                        p += 3
                else:
                    p += 3
        elif byte == 0x48 and p + 2 < len(data) and data[p+1] == 0x83 and data[p+2] == 0xF9:
            if p + 3 < len(data):
                imm = data[p+3]
                results.append((rva, f"cmp rcx, 0x{imm:02X}"))
                p += 4
        elif byte == 0x85 and p + 1 < len(data) and data[p+1] == 0xC9:
            results.append((rva, "test ecx, ecx"))
            p += 2
        elif byte >= 0x70 and byte <= 0x7F:
            if p + 1 < len(data):
                rel = struct.unpack('<b', data[p+1:p+2])[0]
                target = p + 2 + rel
                target_rva = get_rva_from_offset(sections, target)
                results.append((rva, f"jcc 0x{target_rva:08X}"))
                p += 2
        elif byte == 0x0F and p + 1 < len(data) and 0x80 <= data[p+1] <= 0x8F:
            if p + 5 < len(data):
                rel = struct.unpack('<i', data[p+2:p+6])[0]
                target = p + 6 + rel
                target_rva = get_rva_from_offset(sections, target)
                results.append((rva, f"jcc 0x{target_rva:08X}"))
                p += 6
        else:
            p += 1
    return results

def find_function_start(data, sections, offset):
    """Find function start by looking for prologue"""
    text = sections.get('.text', {})
    text_start = text.get('raw', 0)
    # Look backwards for typical prologue patterns
    for back in range(min(128, offset - text_start)):
        pos = offset - back
        if pos < text_start:
            break
        # push rbp
        if data[pos] == 0x55:
            # Check next few bytes for mov rsp, rbp or sub rsp
            if pos + 2 < len(data):
                if data[pos+1:pos+3] == b'\x48\x89':  # mov [rsp+8], rbx etc
                    continue
                if data[pos+1] == 0x48 and data[pos+2] == 0x89 and data[pos+3] == 0xE5:  # mov rbp, rsp
                    return pos
                if data[pos+1] == 0x48 and data[pos+2] == 0x83 and data[pos+3] == 0xEC:  # sub rsp, imm
                    return pos
        # sub rsp, imm (no frame pointer)
        if data[pos] == 0x48 and data[pos+1] == 0x83 and data[pos+2] == 0xEC:
            return pos
        # xor eax, eax at start
        if data[pos] == 0x33 and data[pos+1] == 0xC0:
            # Check if preceded by nothing or ret
            if pos == text_start or data[pos-1] == 0xC3 or data[pos-1] == 0xC2:
                return pos
    return offset

def main():
    global sections
    data = read_exe()
    sections = get_section_info(data)

    if not sections:
        print("Failed to parse PE sections")
        return

    print("Sections:")
    for name, sec in sections.items():
        print(f"  {name}: RVA=0x{sec['rva']:08X}-0x{sec['rva']+sec['size']:08X}, raw=0x{sec['raw']:08X}-0x{sec['raw']+sec['size']:08X}")

    # Search for relevant strings
    patterns = [
        b'Simulation',
        b'SIMULATION',
        b'simulation',
        b'GetSimObject',
        b'getSimObject',
        b'GetInstance',
        b'getInstance',
        b'LocalPlayer',
        b'localPlayer',
        b'PlayerController',
        b'playerController',
        b'WeiShen',
        b'WEISHEN',
        b'Wei Shen',
        b'qSymbol',
        b'SimObject',
        b'simObject',
    ]

    print("\n=== String search ===")
    results = search_strings(data, patterns)
    for pattern, matches in results.items():
        if matches:
            print(f"\n  '{pattern.decode()}': {len(matches)} matches")
            for rva, pos in matches[:20]:  # Limit to first 20
                section = None
                for name, sec in sections.items():
                    if sec['rva'] <= rva < sec['rva'] + sec['size']:
                        section = name
                        break
                print(f"    RVA 0x{rva:08X} (file 0x{pos:08X}) in {section}")
                # Show context
                start = max(0, pos - 32)
                end = min(len(data), pos + 64)
                context = data[start:end]
                print(f"    Context: {context}")

    # Now search for functions that look like GetSimObject
    # Pattern: takes qSymbol* in rcx/rdx, returns SimObject* in rax
    # Often: test rcx/rdx, jz; then some lookup; ret

    print("\n=== Searching for GetSimObject pattern (takes qSymbol*, returns SimObject*) ===")
    # Look for functions with string "GetSimObject" or similar nearby
    for pattern in [b'GetSimObject', b'getSimObject']:
        if pattern in results and results[pattern]:
            for rva, pos in results[pattern]:
                # Look for code references to this string
                # The string might be in .rdata, referenced by code
                pass

    # Search for function that loads a global pointer (MOV RAX, [RIP+disp32]; RET)
    # which could be Simulation::GetInstance()
    print("\n=== Simple global getters (MOV RAX, [RIP+disp32]; RET) ===")
    text = sections.get('.text', {})
    text_start = text.get('raw', 0)
    text_end = text_start + text.get('size', 0)
    data_sec = sections.get('.data', {})
    rdata_sec = sections.get('.rdata', {})

    getter_pattern = b'\x48\x8B\x05....\xC3'  # mov rax, [rip+disp32]; ret
    for m in re.finditer(getter_pattern, data):
        pos = m.start()
        if text_start <= pos < text_end:
            disp = struct.unpack('<i', data[pos+3:pos+7])[0]
            target_rva = get_rva_from_offset(sections, pos + 7 + disp)
            func_rva = get_rva_from_offset(sections, pos)
            if func_rva and target_rva:
                # Check if target is in .data or .rdata
                target_section = None
                for name, sec in sections.items():
                    if sec['rva'] <= target_rva < sec['rva'] + sec['size']:
                        target_section = name
                        break
                if target_section in ('.data', '.rdata'):
                    print(f"  RVA 0x{func_rva:08X}: MOV RAX, [RIP+0x{disp:08X}] -> 0x{target_rva:08X} ({target_section})")

    data.close()

if __name__ == "__main__":
    main()