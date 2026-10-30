#!/usr/bin/env python3
"""
Analyze Simulation vtable functions
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

    # Check ImageBase
    image_base = struct.unpack('<Q', data[pe_offset+48:pe_offset+56])[0]
    print(f"PE ImageBase: 0x{image_base:016X}")

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
    print(f".text RVA: 0x{text_rva_base:08X} - 0x{text_rva_base + text_sec['size']:08X}")

    # The vtable entries are VAs (virtual addresses)
    # VA = ImageBase + RVA
    # So RVA = VA - ImageBase
    image_base = 0x140000000

    # Analyze vtable at 0x01FA0E58 entries
    entries_va = [
        0x143048C, 0x1430498, 0x14304A4, 0x14304B0, 0x14304BC,
        0x14304C8, 0x14304D4, 0x14304E0, 0x14304EC, 0x14304F8,
        0x1430504, 0x1430510, 0x143051C, 0x1430528, 0x1430534
    ]

    print("\n=== Analyzing vtable entries ===")
    for idx, func_va in enumerate(entries_va):
        func_rva = func_va - image_base
        print(f"\n  [{idx}] VA: 0x{func_va:08X} -> RVA: 0x{func_rva:08X}")
        offset = rva_to_offset(func_rva)
        if offset:
            func_bytes = data[offset:offset+64]
            print(f"      Bytes: {func_bytes.hex()[:64]}")
            # Quick classification
            if func_bytes[0] == 0xC3:
                print(f"      -> RET only (stub)")
            elif func_bytes[0:3] == b'\x48\x8B\xC1':  # mov rax, rcx
                if len(func_bytes) > 3 and func_bytes[3] == 0xC3:
                    print(f"      -> mov rax, rcx; ret (getter)")
                else:
                    print(f"      -> mov rax, rcx; ...")
            elif func_bytes[0] == 0xE9:  # JMP rel32
                rel = struct.unpack('<i', func_bytes[1:5])[0]
                target = func_rva + 5 + rel
                print(f"      -> JMP to 0x{target:08X} (thunk)")
            elif func_bytes[0] == 0xEB:  # JMP rel8
                rel = struct.unpack('<b', func_bytes[1:2])[0]
                target = func_rva + 2 + rel
                print(f"      -> JMP short to 0x{target:08X} (thunk)")
            elif func_bytes[0] == 0x48 and func_bytes[1] == 0x83 and func_bytes[2] == 0xEC:
                print(f"      -> sub rsp (function prologue)")
            elif func_bytes[0] == 0x55:
                print(f"      -> push rbp (function prologue)")
            elif func_bytes[0] == 0x53:
                print(f"      -> push rbx (function prologue)")
            else:
                print(f"      -> other")

    # Now analyze the first entry (index 0) in detail
    func_va = entries_va[0]
    func_rva = func_va - image_base
    offset = rva_to_offset(func_rva)
    if offset:
        print(f"\n=== Detailed analysis of vtable[0] at RVA 0x{func_rva:08X} ===")
        func_bytes = data[offset:offset+200]
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
            elif byte == 0xE9 and p + 4 < len(func_bytes):
                rel = struct.unpack('<i', func_bytes[p+1:p+5])[0]
                target = addr + 5 + rel
                print(f"  0x{addr:08X}: jmp 0x{target:08X}")
                p += 5
            elif byte == 0xEB and p + 1 < len(func_bytes):
                rel = struct.unpack('<b', func_bytes[p+1:p+2])[0]
                target = addr + 2 + rel
                print(f"  0x{addr:08X}: jmp short 0x{target:08X}")
                p += 2
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

if __name__ == "__main__":
    main()