#!/usr/bin/env python3
"""
Analyze GameState vtable with VA entries
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
    rdata_sec = next(s for s in sections if s['name'] == '.rdata')
    rdata_data = data[rdata_sec['raw']:rdata_sec['raw'] + rdata_sec['size']]

    # The vtable at 0x01AAAF58 has first entry 0x0000000140E2C240
    # Convert to RVA: 0x140E2C240 - ImageBase(0x140000000) = 0xE2C240
    vtable_rva = 0x01AAAF58
    vtable_offset = vtable_rva - rdata_sec['rva']

    print("=== GameState vtable at RVA 0x01AAAF58 (with VA entries) ===")
    for i in range(15):
        if vtable_offset + i*8 + 8 <= len(rdata_data):
            val = struct.unpack('<Q', rdata_data[vtable_offset + i*8:vtable_offset + i*8 + 8])[0]
            if val >= image_base:
                func_rva = val - image_base
                if text_sec['rva'] <= func_rva < text_sec['rva'] + text_sec['size']:
                    print(f"  [{i}] VA 0x{val:016X} -> RVA 0x{func_rva:08X} (.text+0x{func_rva-text_sec['rva']:X})")
                else:
                    print(f"  [{i}] VA 0x{val:016X} -> RVA 0x{func_rva:08X} (outside .text)")
            else:
                print(f"  [{i}] VA 0x{val:016X} (below ImageBase)")
            if i >= 5 and val == 0:
                break

    # Analyze vtable[0] (OnEnter) at RVA 0xE2C240
    print("\n=== GameState::OnEnter at RVA 0x00E2C240 ===")
    offset = rva_to_offset(0x00E2C240)
    if offset:
        func_bytes = data[offset:offset+200]
        print(f"  Bytes: {func_bytes.hex()[:200]}")
        p = 0
        while p < min(150, len(func_bytes)):
            byte = func_bytes[p]
            addr = 0x00E2C240 + p
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
                    elif modrm == 0x41 and p + 3 < len(func_bytes) and func_bytes[p+3] == 0x20:
                        print(f"  0x{addr:08X}: mov rax, [rcx+0x20]  <-- Loads Simulation pointer!")
                        p += 4
                    else:
                        p += 1
                elif next_byte == 0x8D and p + 2 < len(func_bytes):
                    modrm = func_bytes[p+2]
                    if modrm == 0x05 and p + 6 < len(func_bytes):
                        disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                        target = addr + 7 + disp
                        print(f"  0x{addr:08X}: lea rax, [rip+0x{disp:08X}] -> 0x{target:08X}")
                        p += 7
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

    # Analyze vtable[1] (OnUpdate)
    if vtable_offset + 8 + 8 <= len(rdata_data):
        val = struct.unpack('<Q', rdata_data[vtable_offset + 8:vtable_offset + 16])[0]
        if val >= image_base:
            func_rva = val - image_base
            print(f"\n=== GameState::OnUpdate at RVA 0x{func_rva:08X} ===")
            offset = rva_to_offset(func_rva)
            if offset:
                func_bytes = data[offset:offset+200]
                print(f"  Bytes: {func_bytes.hex()[:200]}")
                p = 0
                while p < min(150, len(func_bytes)):
                    byte = func_bytes[p]
                    addr = func_rva + p
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
                            elif modrm == 0x41 and p + 3 < len(func_bytes) and func_bytes[p+3] == 0x20:
                                print(f"  0x{addr:08X}: mov rax, [rcx+0x20]  <-- Loads Simulation pointer!")
                                p += 4
                            else:
                                p += 1
                        elif next_byte == 0x8D and p + 2 < len(func_bytes):
                            modrm = func_bytes[p+2]
                            if modrm == 0x05 and p + 6 < len(func_bytes):
                                disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                                target = addr + 7 + disp
                                print(f"  0x{addr:08X}: lea rax, [rip+0x{disp:08X}] -> 0x{target:08X}")
                                p += 7
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

if __name__ == "__main__":
    main()