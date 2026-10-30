#!/usr/bin/env python3
"""
Search for Simulation::GetSimObject by signature pattern
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

    # Search for functions with pattern:
    # - Function prologue (push rbx/push rsi/push rdi / sub rsp)
    # - test rdx, rdx (check qSymbol parameter)
    # - jz/jnz (handle null)
    # - ... lookup logic ...
    # - ret (return SimObject* in RAX)

    print("=== Searching for GetSimObject pattern ===")
    # Look for: test rdx, rdx (48 85 D2) near function start
    for i in range(len(text_data) - 3):
        if text_data[i:i+3] == b'\x48\x85\xD2':  # test rdx, rdx
            code_rva = text_rva_base + i
            # Check if this is near a function prologue (within 32 bytes before)
            is_function = False
            func_start = code_rva
            for back in range(1, 32):
                check_rva = code_rva - back
                check_offset = rva_to_offset(check_rva)
                if check_offset and check_offset + 4 <= len(data):
                    check_bytes = data[check_offset:check_offset+4]
                    if check_bytes[0] == 0x48 and check_bytes[1] == 0x83 and check_bytes[2] == 0xEC:
                        func_start = check_rva
                        is_function = True
                        break
                    if check_bytes[0] == 0x55 and check_bytes[1] == 0x48 and check_bytes[2] == 0x8B and check_bytes[3] == 0xEC:
                        func_start = check_rva
                        is_function = True
                        break
                    if check_bytes[0] == 0x53 and check_offset + 3 < len(data):
                        next_b = data[check_offset+1:check_offset+4]
                        if next_b[0] == 0x48 and next_b[1] == 0x83 and next_b[2] == 0xEC:
                            func_start = check_rva
                            is_function = True
                            break
                    if check_bytes[0] == 0x48 and check_bytes[1] == 0x89 and check_bytes[2] == 0x5C:
                        func_start = check_rva
                        is_function = True
                        break
            if is_function:
                # Look ahead for ret
                ahead = text_data[i:i+100]
                if b'\xC3' in ahead[:80]:
                    print(f"\n  Candidate at RVA 0x{code_rva:08X} (func at 0x{func_start:08X})")
                    func_offset = rva_to_offset(func_start)
                    if func_offset:
                        func_bytes = data[func_offset:func_offset+120]
                        print(f"    Bytes: {func_bytes.hex()[:120]}")
                        # Disassemble first 60 bytes
                        p = 0
                        while p < min(60, len(func_bytes)):
                            byte = func_bytes[p]
                            addr = func_start + p
                            if byte == 0xC3:
                                print(f"    0x{addr:08X}: ret")
                                p += 1
                                break
                            elif byte == 0xE8 and p + 4 < len(func_bytes):
                                rel = struct.unpack('<i', func_bytes[p+1:p+5])[0]
                                target = addr + 5 + rel
                                print(f"    0x{addr:08X}: call 0x{target:08X}")
                                p += 5
                            elif byte == 0x48 and p + 1 < len(func_bytes):
                                next_byte = func_bytes[p+1]
                                if next_byte == 0x85 and p + 2 < len(func_bytes) and func_bytes[p+2] == 0xD2:
                                    print(f"    0x{addr:08X}: test rdx, rdx")
                                    p += 3
                                elif next_byte == 0x8D and p + 2 < len(func_bytes):
                                    modrm = func_bytes[p+2]
                                    if modrm == 0x0D and p + 6 < len(func_bytes):
                                        disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                                        target = addr + 7 + disp
                                        print(f"    0x{addr:08X}: lea rcx, [rip+0x{disp:08X}] -> 0x{target:08X}")
                                        p += 7
                                    elif modrm == 0x15 and p + 6 < len(func_bytes):
                                        disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                                        target = addr + 7 + disp
                                        print(f"    0x{addr:08X}: lea rdx, [rip+0x{disp:08X}] -> 0x{target:08X}")
                                        p += 7
                                    elif modrm == 0x35 and p + 6 < len(func_bytes):
                                        disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                                        target = addr + 7 + disp
                                        print(f"    0x{addr:08X}: lea rsi, [rip+0x{disp:08X}] -> 0x{target:08X}")
                                        p += 7
                                    else:
                                        p += 1
                                elif next_byte == 0x8B and p + 2 < len(func_bytes):
                                    modrm = func_bytes[p+2]
                                    if modrm == 0x05 and p + 6 < len(func_bytes):
                                        disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                                        target = addr + 7 + disp
                                        print(f"    0x{addr:08X}: mov rax, [rip+0x{disp:08X}] -> 0x{target:08X}")
                                        p += 7
                                    elif modrm == 0xC1:
                                        print(f"    0x{addr:08X}: mov rax, rcx")
                                        p += 3
                                    else:
                                        p += 1
                                elif next_byte == 0x83 and p + 3 < len(func_bytes):
                                    if func_bytes[p+2] == 0xEC:
                                        imm = func_bytes[p+3]
                                        print(f"    0x{addr:08X}: sub rsp, 0x{imm:02X}")
                                        p += 4
                                    else:
                                        p += 1
                                elif next_byte == 0x89 and p + 2 < len(func_bytes):
                                    modrm = func_bytes[p+2]
                                    if modrm == 0xC2:  # MOV RDX, RAX
                                        print(f"    0x{addr:08X}: mov rdx, rax")
                                        p += 3
                                    elif modrm == 0xD0:  # MOV RAX, RDX
                                        print(f"    0x{addr:08X}: mov rax, rdx")
                                        p += 3
                                    else:
                                        p += 1
                                else:
                                    p += 1
                            elif byte == 0x74 and p + 1 < len(func_bytes):
                                rel = struct.unpack('<b', func_bytes[p+1:p+2])[0]
                                target = addr + 2 + rel
                                print(f"    0x{addr:08X}: jz 0x{target:08X}")
                                p += 2
                            elif byte == 0x75 and p + 1 < len(func_bytes):
                                rel = struct.unpack('<b', func_bytes[p+1:p+2])[0]
                                target = addr + 2 + rel
                                print(f"    0x{addr:08X}: jnz 0x{target:08X}")
                                p += 2
                            elif byte == 0x0F and p + 1 < len(func_bytes) and 0x80 <= func_bytes[p+1] <= 0x8F:
                                if p + 5 < len(func_bytes):
                                    rel = struct.unpack('<i', func_bytes[p+2:p+6])[0]
                                    target = addr + 6 + rel
                                    print(f"    0x{addr:08X}: jcc 0x{target:08X}")
                                    p += 6
                                else:
                                    p += 1
                            elif byte == 0xEB and p + 1 < len(func_bytes):
                                rel = struct.unpack('<b', func_bytes[p+1:p+2])[0]
                                target = addr + 2 + rel
                                print(f"    0x{addr:08X}: jmp short 0x{target:08X}")
                                p += 2
                            elif byte == 0x53:
                                print(f"    0x{addr:08X}: push rbx")
                                p += 1
                            elif byte == 0x56:
                                print(f"    0x{addr:08X}: push rsi")
                                p += 1
                            elif byte == 0x57:
                                print(f"    0x{addr:08X}: push rdi")
                                p += 1
                            elif byte == 0x41 and p + 1 < len(func_bytes) and 0x50 <= func_bytes[p+1] <= 0x57:
                                print(f"    0x{addr:08X}: push r{func_bytes[p+1]-0x50}")
                                p += 2
                            elif byte == 0x48 and p + 1 < len(func_bytes):
                                p += 1
                            else:
                                p += 1

if __name__ == "__main__":
    main()