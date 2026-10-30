#!/usr/bin/env python3
"""
Analyze qSymbol CRC32 constructor function
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

    # Analyze from 0x00E95E88 onwards
    func_start = 0x00E95E88
    print(f"=== Analyzing function at RVA 0x{func_start:08X} ===")
    offset = rva_to_offset(func_start)
    if offset:
        func_bytes = data[offset:offset+200]
        print(f"Raw bytes: {func_bytes.hex()}")
        p = 0
        while p < min(180, len(func_bytes)):
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
            elif byte == 0x74 and p + 1 < len(func_bytes):
                rel = struct.unpack('<b', func_bytes[p+1:p+2])[0]
                target = addr + 2 + rel
                print(f"  0x{addr:08X}: jz 0x{target:08X}")
                p += 2
            elif byte == 0x75 and p + 1 < len(func_bytes):
                rel = struct.unpack('<b', func_bytes[p+1:p+2])[0]
                target = addr + 2 + rel
                print(f"  0x{addr:08X}: jnz 0x{target:08X}")
                p += 2
            elif byte == 0x48 and p + 1 < len(func_bytes):
                next_byte = func_bytes[p+1]
                if next_byte == 0x85 and p + 2 < len(func_bytes) and func_bytes[p+2] == 0xD2:
                    print(f"  0x{addr:08X}: test rdx, rdx")
                    p += 3
                elif next_byte == 0x83 and p + 3 < len(func_bytes):
                    if func_bytes[p+2] == 0xEC:
                        imm = func_bytes[p+3]
                        print(f"  0x{addr:08X}: sub rsp, 0x{imm:02X}")
                        p += 4
                    else:
                        p += 1
                elif next_byte == 0x8D and p + 2 < len(func_bytes):
                    modrm = func_bytes[p+2]
                    if modrm == 0x3D and p + 6 < len(func_bytes):
                        disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                        target = addr + 7 + disp
                        print(f"  0x{addr:08X}: lea rdi, [rip+0x{disp:08X}] -> 0x{target:08X}")
                        p += 7
                    elif modrm == 0x15 and p + 6 < len(func_bytes):
                        disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                        target = addr + 7 + disp
                        print(f"  0x{addr:08X}: lea rdx, [rip+0x{disp:08X}] -> 0x{target:08X}")
                        p += 7
                    elif modrm == 0x0D and p + 6 < len(func_bytes):
                        disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                        target = addr + 7 + disp
                        print(f"  0x{addr:08X}: lea rcx, [rip+0x{disp:08X}] -> 0x{target:08X}")
                        p += 7
                    else:
                        p += 1
                elif next_byte == 0x0F and p + 2 < len(func_bytes):
                    if func_bytes[p+2] == 0xB6:
                        modrm = func_bytes[p+3]
                        reg = (modrm >> 3) & 7
                        rm = modrm & 7
                        reg_names = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
                        if rm == 4 and p + 4 < len(func_bytes):
                            sib = func_bytes[p+4]
                            base = sib & 7
                            index = (sib >> 3) & 7
                            scale = sib >> 6
                            print(f"  0x{addr:08X}: movzx {reg_names[reg]}, byte ptr [{reg_names[base]}+{reg_names[index]}*{scale}]")
                            p += 5
                        else:
                            print(f"  0x{addr:08X}: movzx {reg_names[reg]}, byte ptr [{reg_names[rm]}]")
                            p += 4
                    elif func_bytes[p+2] == 0xB7:
                        p += 3
                    else:
                        p += 1
                elif next_byte == 0x8B and p + 2 < len(func_bytes):
                    modrm = func_bytes[p+2]
                    if modrm == 0xC1:
                        print(f"  0x{addr:08X}: mov rax, rcx")
                        p += 3
                    elif modrm == 0xD8:
                        print(f"  0x{addr:08X}: mov rbx, rax")
                        p += 3
                    elif modrm == 0xF8:
                        print(f"  0x{addr:08X}: mov rdi, rax")
                        p += 3
                    else:
                        p += 1
                elif next_byte == 0xC1 and p + 2 < len(func_bytes):
                    if func_bytes[p+2] == 0xE8:
                        print(f"  0x{addr:08X}: shr rax, 8")
                        p += 3
                    elif func_bytes[p+2] == 0xEB:
                        print(f"  0x{addr:08X}: shr rbx, 8")
                        p += 3
                    else:
                        p += 1
                elif next_byte == 0x33 and p + 2 < len(func_bytes):
                    modrm = func_bytes[p+2]
                    if modrm == 0xC1:
                        print(f"  0x{addr:08X}: xor rax, rcx")
                        p += 3
                    elif modrm == 0xDB:
                        print(f"  0x{addr:08X}: xor rbx, rbx")
                        p += 3
                    else:
                        p += 1
                else:
                    p += 1
            elif byte == 0x41 and p + 1 < len(func_bytes):
                next_byte = func_bytes[p+1]
                if 0xB6 <= next_byte <= 0xB7:
                    reg = next_byte - 0xB0
                    modrm = func_bytes[p+2]
                    rm = modrm & 7
                    reg_names = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
                    print(f"  0x{addr:08X}: movzx r{reg}, byte ptr [{reg_names[rm]}]")
                    p += 3
                elif next_byte == 0x8B:
                    p += 1
                elif next_byte == 0x33:
                    modrm = func_bytes[p+2]
                    if modrm == 0xC8:
                        print(f"  0x{addr:08X}: xor r8, rcx")
                        p += 3
                    else:
                        p += 1
                else:
                    p += 1
            elif byte == 0x44 and p + 1 < len(func_bytes):
                p += 1
            elif byte == 0x48 and p + 1 < len(func_bytes) and func_bytes[p+1] == 0x89:
                p += 1
            elif byte == 0xC1 and p + 1 < len(func_bytes):
                p += 1
            elif byte == 0x8B and p + 1 < len(func_bytes):
                p += 1
            elif byte == 0x33 and p + 1 < len(func_bytes):
                p += 1
            elif byte == 0x45 and p + 1 < len(func_bytes):
                p += 1
            else:
                p += 1

if __name__ == "__main__":
    main()