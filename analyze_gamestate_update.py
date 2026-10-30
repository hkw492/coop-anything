#!/usr/bin/env python3
"""
Analyze the real GameState::OnUpdate at 0x00E28610
"""

import struct
from pathlib import Path

EXE_PATH = Path(r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe")

def main():
    with open(EXE_PATH, "rb") as f:
        data = f.read()

    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    image_base = struct.unpack('<Q', data[pe_offset+48:pe_offset+56])[0]
    print(f"ImageBase: 0x{image_base:016X}")

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

    # Analyze the function at 0x00E28610 (previously found as GameState::OnUpdate)
    print("=== Function at RVA 0x00E28610 (real GameState::OnUpdate?) ===")
    offset = rva_to_offset(0x00E28610)
    if offset:
        func_bytes = data[offset:offset+200]
        print(f"  Bytes: {func_bytes.hex()[:200]}")
        p = 0
        while p < min(150, len(func_bytes)):
            byte = func_bytes[p]
            addr = 0x00E28610 + p
            if byte == 0xC3:
                print(f"  0x{addr:08X}: ret")
                p += 1
                break
            elif byte == 0xE8 and p + 4 < len(func_bytes):
                rel = struct.unpack('<i', func_bytes[p+1:p+5])[0]
                target = addr + 5 + rel
                print(f"  0x{addr:08X}: call 0x{target:08X}")
                p += 5
            elif byte == 0xE9 and p + 4 < len(func_bytes):
                rel = struct.unpack('<i', func_bytes[p+1:p+5])[0]
                target = addr + 5 + rel
                print(f"  0x{addr:08X}: jmp 0x{target:08X}")
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
                    elif modrm == 0x41 and p + 3 < len(func_bytes) and func_bytes[p+3] == 0x20:
                        print(f"  0x{addr:08X}: mov rax, [rcx+0x20]  <-- Loads Simulation pointer!")
                        p += 4
                    elif modrm == 0x01:
                        print(f"  0x{addr:08X}: mov rax, [rcx]")
                        p += 3
                    else:
                        p += 1
                elif next_byte == 0x8D and p + 2 < len(func_bytes):
                    modrm = func_bytes[p+2]
                    if modrm == 0x05 and p + 6 < len(func_bytes):
                        disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                        target = addr + 7 + disp
                        print(f"  0x{addr:08X}: lea rax, [rip+0x{disp:08X}] -> 0x{target:08X}")
                        p += 7
                    elif modrm == 0x41 and p + 3 < len(func_bytes) and func_bytes[p+3] == 0x20:
                        print(f"  0x{addr:08X}: lea rax, [rcx+0x20]")
                        p += 4
                    else:
                        p += 1
                elif next_byte == 0x89 and p + 2 < len(func_bytes):
                    modrm = func_bytes[p+2]
                    if modrm == 0x41 and p + 3 < len(func_bytes) and func_bytes[p+3] == 0x20:
                        print(f"  0x{addr:08X}: mov [rcx+0x20], rax  <-- Stores Simulation pointer!")
                        p += 4
                    else:
                        p += 1
                else:
                    p += 1
            else:
                p += 1

    # Also check the thunk at 0x00C55270
    print("\n=== Thunk at RVA 0x00C55270 ===")
    offset = rva_to_offset(0x00C55270)
    if offset:
        func_bytes = data[offset:offset+32]
        print(f"  Bytes: {func_bytes.hex()}")
        p = 0
        while p < min(20, len(func_bytes)):
            byte = func_bytes[p]
            addr = 0x00C55270 + p
            if byte == 0x48 and p + 1 < len(func_bytes):
                next_byte = func_bytes[p+1]
                if next_byte == 0x8B and p + 2 < len(func_bytes):
                    modrm = func_bytes[p+2]
                    if modrm == 0x01:
                        print(f"  0x{addr:08X}: mov rax, [rcx]  <-- Load vtable from object")
                        p += 3
                    elif modrm == 0x05 and p + 6 < len(func_bytes):
                        disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                        target = addr + 7 + disp
                        print(f"  0x{addr:08X}: mov rax, [rip+0x{disp:08X}] -> 0x{target:08X}")
                        p += 7
                    else:
                        p += 1
                elif next_byte == 0xFF and p + 2 < len(func_bytes):
                    modrm = func_bytes[p+2]
                    if modrm == 0x20:
                        print(f"  0x{addr:08X}: jmp [rax]  <-- Call first virtual function")
                        p += 3
                    else:
                        p += 1
                else:
                    p += 1
            elif byte == 0xFF and p + 1 < len(func_bytes):
                if func_bytes[p+1] == 0x20:
                    print(f"  0x{addr:08X}: jmp [rax]")
                    p += 2
                else:
                    p += 1
            else:
                p += 1

    # Search for where GameState+0x20 gets initialized (mov [rcx+0x20], rax)
    print("\n=== Searching for 'mov [rcx+0x20], rax' pattern ===")
    text_data = data[text_sec['raw']:text_sec['raw'] + text_sec['size']]
    for i in range(len(text_data) - 4):
        # 48 89 41 20 = mov [rcx+0x20], rax
        if text_data[i:i+4] == b'\x48\x89\x41\x20':
            addr = text_sec['rva'] + i
            print(f"  Found at RVA 0x{addr:08X}")
            # Show context
            ctx = data[text_sec['raw'] + max(0,i-16):text_sec['raw'] + i + 20].hex()
            print(f"    Context: {ctx}")

if __name__ == "__main__":
    main()