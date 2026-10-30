#!/usr/bin/env python3
"""
Analyze functions that initialize GameState+0x20 with Simulation pointer
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
    rdata_sec = next(s for s in sections if s['name'] == '.rdata')

    # Check what's at .rdata 0x01AC34F8 and 0x01AC34E0
    print("=== .rdata pointers at 0x01AC34F8 and 0x01AC34E0 ===")
    for ptr_rva in [0x01AC34F8, 0x01AC34E0]:
        offset = rva_to_offset(ptr_rva)
        if offset:
            val = struct.unpack('<Q', data[offset:offset+8])[0]
            print(f"  Pointer at RVA 0x{ptr_rva:08X}: 0x{val:016X}")
            if rdata_sec['rva'] <= val < rdata_sec['rva'] + rdata_sec['size']:
                print(f"    -> Points to .rdata (vtable?) at RVA 0x{val:016X}")
            elif text_sec['rva'] <= val < text_sec['rva'] + text_sec['size']:
                print(f"    -> Points to .text at RVA 0x{val:08X}")

    # Analyze function at 0x00E976B2
    print("\n=== Function at RVA 0x00E976B2 ===")
    offset = rva_to_offset(0x00E976B2)
    if offset:
        for back in range(0, 128):
            check_off = offset - back
            if check_off >= 0:
                byte = data[check_off]
                addr = 0x00E976B2 - back
                if byte == 0x48 and check_off + 1 < len(data):
                    next_byte = data[check_off+1]
                    if next_byte == 0x83 and check_off + 3 < len(data) and data[check_off+2] == 0xEC:
                        print(f"  Function prologue at RVA 0x{addr:08X}: sub rsp, 0x{data[check_off+3]:02X}")
                        func_start = addr
                        break
                    elif byte in (0x55, 0x53, 0x56, 0x57):
                        print(f"  Function prologue at RVA 0x{addr:08X}: push")
                        func_start = addr
                        break
                    elif byte == 0x40 and check_off + 1 < len(data) and data[check_off+1] == 0x57:
                        print(f"  Function prologue at RVA 0x{addr:08X}: push rdi")
                        func_start = addr
                        break
        else:
            func_start = 0x00E97650

        func_off = rva_to_offset(func_start)
        if func_off:
            func_bytes = data[func_off:func_off+150]
            p = 0
            while p < min(120, len(func_bytes)):
                byte = func_bytes[p]
                addr = func_start + p
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
                        else:
                            p += 1
                    elif next_byte == 0x89 and p + 2 < len(func_bytes):
                        modrm = func_bytes[p+2]
                        if modrm == 0x41 and p + 3 < len(func_bytes) and func_bytes[p+3] == 0x20:
                            print(f"  0x{addr:08X}: mov [rcx+0x20], rax")
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
                    else:
                        p += 1
                else:
                    p += 1

    # Analyze function at 0x00E97ED1
    print("\n=== Function at RVA 0x00E97ED1 ===")
    offset = rva_to_offset(0x00E97ED1)
    if offset:
        for back in range(0, 128):
            check_off = offset - back
            if check_off >= 0:
                byte = data[check_off]
                addr = 0x00E97ED1 - back
                if byte == 0x48 and check_off + 1 < len(data):
                    next_byte = data[check_off+1]
                    if next_byte == 0x83 and check_off + 3 < len(data) and data[check_off+2] == 0xEC:
                        print(f"  Function prologue at RVA 0x{addr:08X}: sub rsp, 0x{data[check_off+3]:02X}")
                        func_start = addr
                        break
                    elif byte in (0x55, 0x53, 0x56, 0x57):
                        print(f"  Function prologue at RVA 0x{addr:08X}: push")
                        func_start = addr
                        break
                    elif byte == 0x40 and check_off + 1 < len(data) and data[check_off+1] == 0x57:
                        print(f"  Function prologue at RVA 0x{addr:08X}: push rdi")
                        func_start = addr
                        break
        else:
            func_start = 0x00E97E70

        func_off = rva_to_offset(func_start)
        if func_off:
            func_bytes = data[func_off:func_off+150]
            p = 0
            while p < min(120, len(func_bytes)):
                byte = func_bytes[p]
                addr = func_start + p
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
                        else:
                            p += 1
                    elif next_byte == 0x89 and p + 2 < len(func_bytes):
                        modrm = func_bytes[p+2]
                        if modrm == 0x41 and p + 3 < len(func_bytes) and func_bytes[p+3] == 0x20:
                            print(f"  0x{addr:08X}: mov [rcx+0x20], rax")
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
                    else:
                        p += 1
                else:
                    p += 1

if __name__ == "__main__":
    main()