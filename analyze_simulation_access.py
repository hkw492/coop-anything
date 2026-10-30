#!/usr/bin/env python3
"""
Analyze GameState vtable and Simulation access
"""

import struct
from pathlib import Path

EXE_PATH = Path(r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe")

def main():
    with open(EXE_PATH, "rb") as f:
        data = f.read()

    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    num_sections = struct.unpack('<H', data[pe_offset+6:pe_offset+8])[0]
    opt_header_size = struct.unpack('<H', data[pe_offset+20:pe_offset+22])[0]
    sections_start = pe_offset + 24 + opt_header_size

    sections = []
    for i in range(num_sections):
        sec = sections_start + i * 40
        name = data[sec:sec+8].rstrip(b'\0').decode('ascii', errors='ignore')
        sec_rva = struct.unpack('<I', data[sec+12:sec+16])[0]
        sec_size = struct.unpack('<I', data[sec+16:sec+20])[0]
        sec_raw = struct.unpack('<I', data[sec+20:sec+24])[0]
        sections.append({'name': name, 'rva': sec_rva, 'size': sec_size, 'raw': sec_raw})

    def rva_to_offset(rva):
        for sec in sections:
            if sec['rva'] <= rva < sec['rva'] + sec['size']:
                return sec['raw'] + (rva - sec['rva'])
        return None

    text_sec = next(s for s in sections if s['name'] == '.text')
    text_data = data[text_sec['raw']:text_sec['raw'] + text_sec['size']]
    text_rva_base = text_sec['rva']
    rdata_sec = next(s for s in sections if s['name'] == '.rdata')
    rdata_data = data[rdata_sec['raw']:rdata_sec['raw'] + rdata_sec['size']]
    rdata_rva_base = rdata_sec['rva']

    # Check GameState vtable at 0x01AABF48 (from constructor lea)
    print("=== GameState vtable at RVA 0x01AABF48 ===")
    vtable_rva = 0x01AABF48
    vtable_offset = vtable_rva - rdata_rva_base
    if 0 <= vtable_offset < len(rdata_data) - 8:
        for i in range(15):
            if vtable_offset + i*8 + 8 <= len(rdata_data):
                val = struct.unpack('<Q', rdata_data[vtable_offset + i*8:vtable_offset + i*8 + 8])[0]
                if text_sec['rva'] <= val < text_sec['rva'] + text_sec['size']:
                    print(f"  [{i}] -> 0x{val:016X} (.text+0x{val-text_sec['rva']:X})")
                else:
                    break

    # Analyze function at 0x00C55270 (called with GameState+0x20)
    print("\n=== Function at RVA 0x00C55270 (possible Simulation::Update) ===")
    rva = 0x00C55270
    offset = rva_to_offset(rva)
    if offset:
        func_bytes = data[offset:offset+200]
        print(f"  Bytes: {func_bytes.hex()[:200]}")
        p = 0
        while p < min(150, len(func_bytes)):
            byte = func_bytes[p]
            addr = rva + p
            if byte == 0xC3:
                print(f"  0x{addr:08X}: ret")
                p += 1
                break
            elif byte == 0xE8 and p + 4 < len(func_bytes):
                rel = struct.unpack('<i', func_bytes[p+1:p+5])[0]
                target = addr + 5 + rel
                print(f"  0x{addr:08X}: call 0x{target:08X}")
                p += 5
            elif byte == 0x48 and p + 1 < len(func_bytes):
                next_byte = func_bytes[p+1]
                if next_byte == 0x8B and p + 2 < len(func_bytes):
                    modrm = func_bytes[p+2]
                    if modrm == 0x05 and p + 6 < len(func_bytes):
                        disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                        target = addr + 7 + disp
                        print(f"  0x{addr:08X}: mov rax, [rip+0x{disp:08X}] -> 0x{target:08X}")
                        p += 7
                    elif modrm == 0x0D:
                        print(f"  0x{addr:08X}: mov rcx, [rcx]")
                        p += 3
                    elif modrm == 0xC1:
                        print(f"  0x{addr:08X}: mov rax, rcx")
                        p += 3
                    elif modrm == 0x01:
                        print(f"  0x{addr:08X}: mov rax, [rcx]")
                        p += 3
                    else:
                        p += 1
                elif next_byte == 0x8D and p + 2 < len(func_bytes):
                    modrm = func_bytes[p+2]
                    if modrm == 0x0D and p + 6 < len(func_bytes):
                        disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                        target = addr + 7 + disp
                        print(f"  0x{addr:08X}: lea rcx, [rip+0x{disp:08X}] -> 0x{target:08X}")
                        p += 7
                    elif modrm == 0x15 and p + 6 < len(func_bytes):
                        disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                        target = addr + 7 + disp
                        print(f"  0x{addr:08X}: lea rdx, [rip+0x{disp:08X}] -> 0x{target:08X}")
                        p += 7
                    else:
                        p += 1
                elif next_byte == 0x83 and p + 3 < len(func_bytes):
                    if func_bytes[p+2] == 0xEC:
                        imm = func_bytes[p+3]
                        print(f"  0x{addr:08X}: sub rsp, 0x{imm:02X}")
                        p += 4
                    else:
                        p += 1
                elif next_byte == 0x89 and p + 2 < len(func_bytes):
                    p += 1
                else:
                    p += 1
            elif byte == 0x55:
                print(f"  0x{addr:08X}: push rbp")
                p += 1
            elif byte == 0x53:
                print(f"  0x{addr:08X}: push rbx")
                p += 1
            elif byte == 0x56:
                print(f"  0x{addr:08X}: push rsi")
                p += 1
            elif byte == 0x57:
                print(f"  0x{addr:08X}: push rdi")
                p += 1
            elif byte == 0x41 and p + 1 < len(func_bytes) and 0x50 <= func_bytes[p+1] <= 0x57:
                print(f"  0x{addr:08X}: push r{func_bytes[p+1]-0x50}")
                p += 2
            elif byte == 0x48 and p + 1 < len(func_bytes) and func_bytes[p+1] == 0x89:
                p += 1
            else:
                p += 1

    # Also check function at 0x00D763F0
    print("\n=== Function at RVA 0x00D763F0 ===")
    rva = 0x00D763F0
    offset = rva_to_offset(rva)
    if offset:
        func_bytes = data[offset:offset+100]
        print(f"  Bytes: {func_bytes.hex()[:100]}")
        p = 0
        while p < min(60, len(func_bytes)):
            byte = func_bytes[p]
            addr = rva + p
            if byte == 0xC3:
                print(f"  0x{addr:08X}: ret")
                p += 1
                break
            elif byte == 0xE8 and p + 4 < len(func_bytes):
                rel = struct.unpack('<i', func_bytes[p+1:p+5])[0]
                target = addr + 5 + rel
                print(f"  0x{addr:08X}: call 0x{target:08X}")
                p += 5
            elif byte == 0x48 and p + 1 < len(func_bytes):
                next_byte = func_bytes[p+1]
                if next_byte == 0x8B and p + 2 < len(func_bytes):
                    modrm = func_bytes[p+2]
                    if modrm == 0x05 and p + 6 < len(func_bytes):
                        disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                        target = addr + 7 + disp
                        print(f"  0x{addr:08X}: mov rax, [rip+0x{disp:08X}] -> 0x{target:08X}")
                        p += 7
                    elif modrm == 0x0D:
                        print(f"  0x{addr:08X}: mov rcx, [rcx]")
                        p += 3
                    elif modrm == 0xC1:
                        print(f"  0x{addr:08X}: mov rax, rcx")
                        p += 3
                    elif modrm == 0x01:
                        print(f"  0x{addr:08X}: mov rax, [rcx]")
                        p += 3
                    else:
                        p += 1
                elif next_byte == 0x83 and p + 3 < len(func_bytes):
                    if func_bytes[p+2] == 0xEC:
                        imm = func_bytes[p+3]
                        print(f"  0x{addr:08X}: sub rsp, 0x{imm:02X}")
                        p += 4
                    else:
                        p += 1
                else:
                    p += 1
            elif byte == 0x53:
                print(f"  0x{addr:08X}: push rbx")
                p += 1
            elif byte == 0x56:
                print(f"  0x{addr:08X}: push rsi")
                p += 1
            elif byte == 0x57:
                print(f"  0x{addr:08X}: push rdi")
                p += 1
            elif byte == 0x48 and p + 1 < len(func_bytes) and func_bytes[p+1] == 0x89:
                p += 1
            else:
                p += 1

    # Check function at 0x00E2C220
    print("\n=== Function at RVA 0x00E2C220 ===")
    rva = 0x00E2C220
    offset = rva_to_offset(rva)
    if offset:
        func_bytes = data[offset:offset+100]
        print(f"  Bytes: {func_bytes.hex()[:100]}")
        p = 0
        while p < min(60, len(func_bytes)):
            byte = func_bytes[p]
            addr = rva + p
            if byte == 0xC3:
                print(f"  0x{addr:08X}: ret")
                p += 1
                break
            elif byte == 0xE8 and p + 4 < len(func_bytes):
                rel = struct.unpack('<i', func_bytes[p+1:p+5])[0]
                target = addr + 5 + rel
                print(f"  0x{addr:08X}: call 0x{target:08X}")
                p += 5
            elif byte == 0x48 and p + 1 < len(func_bytes):
                next_byte = func_bytes[p+1]
                if next_byte == 0x8B and p + 2 < len(func_bytes):
                    modrm = func_bytes[p+2]
                    if modrm == 0x05 and p + 6 < len(func_bytes):
                        disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                        target = addr + 7 + disp
                        print(f"  0x{addr:08X}: mov rax, [rip+0x{disp:08X}] -> 0x{target:08X}")
                        p += 7
                    elif modrm == 0x0D:
                        print(f"  0x{addr:08X}: mov rcx, [rcx]")
                        p += 3
                    elif modrm == 0xC1:
                        print(f"  0x{addr:08X}: mov rax, rcx")
                        p += 3
                    elif modrm == 0x01:
                        print(f"  0x{addr:08X}: mov rax, [rcx]")
                        p += 3
                    else:
                        p += 1
                elif next_byte == 0x83 and p + 3 < len(func_bytes):
                    if func_bytes[p+2] == 0xEC:
                        imm = func_bytes[p+3]
                        print(f"  0x{addr:08X}: sub rsp, 0x{imm:02X}")
                        p += 4
                    else:
                        p += 1
                else:
                    p += 1
            elif byte == 0x53:
                print(f"  0x{addr:08X}: push rbx")
                p += 1
            elif byte == 0x56:
                print(f"  0x{addr:08X}: push rsi")
                p += 1
            elif byte == 0x57:
                print(f"  0x{addr:08X}: push rdi")
                p += 1
            else:
                p += 1

if __name__ == "__main__":
    main()