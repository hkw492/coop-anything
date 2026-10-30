#!/usr/bin/env python3
"""
Disassemble GetLocalPlayer function and analyze global getters
"""

import struct
import re
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

    def offset_to_rva(offset):
        for sec in sections:
            if sec['raw'] <= offset < sec['raw'] + sec['size']:
                return sec['rva'] + (offset - sec['raw'])
        return None

    text_sec = None
    data_sec = None
    for sec in sections:
        if sec['name'] == '.text':
            text_sec = sec
        elif sec['name'] == '.data':
            data_sec = sec

    text_data = data[text_sec['raw']:text_sec['raw'] + text_sec['size']]
    text_rva_base = text_sec['rva']
    data_data = data[data_sec['raw']:data_sec['raw'] + data_sec['size']]
    data_rva_base = data_sec['rva']

    # Disassemble GetLocalPlayer at RVA 0x001EDA50
    print("=== GetLocalPlayer at RVA 0x001EDA50 ===")
    rva = 0x001EDA50
    offset = rva_to_offset(rva)
    func_bytes = data[offset:offset+300]

    # Simple disassembly
    p = 0
    while p < len(func_bytes):
        if p >= 250:
            break
        byte = func_bytes[p]
        addr = rva + p

        # Common patterns
        if byte == 0xC3:
            print(f"  0x{addr:08X}: ret")
            break
        elif byte == 0xE8 and p + 4 < len(func_bytes):  # CALL rel32
            rel = struct.unpack('<i', func_bytes[p+1:p+5])[0]
            target = addr + 5 + rel
            print(f"  0x{addr:08X}: call 0x{target:08X}")
            p += 5
        elif byte == 0x48 and p + 1 < len(func_bytes):
            next_byte = func_bytes[p+1]
            if next_byte == 0x8B and p + 2 < len(func_bytes):
                modrm = func_bytes[p+2]
                if modrm == 0x05 and p + 6 < len(func_bytes):  # MOV RAX, [RIP+disp32]
                    disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                    target = addr + 7 + disp
                    print(f"  0x{addr:08X}: mov rax, [rip+0x{disp:08X}] -> 0x{target:08X}")
                    p += 7
                elif modrm == 0x01 and p + 2 < len(func_bytes):  # MOV RAX, [RCX]
                    print(f"  0x{addr:08X}: mov rax, [rcx]")
                    p += 3
                elif modrm == 0x09 and p + 2 < len(func_bytes):  # MOV RCX, [RCX]
                    print(f"  0x{addr:08X}: mov rcx, [rcx]")
                    p += 3
                elif (modrm & 0xC7) == 0x04 and p + 7 < len(func_bytes):  # SIB
                    print(f"  0x{addr:08X}: mov rax, [rcx+...] (SIB)")
                    p += 8
                else:
                    print(f"  0x{addr:08X}: mov rax, [...] (modrm=0x{modrm:02X})")
                    p += 3
            elif next_byte == 0x89 and p + 2 < len(func_bytes):
                modrm = func_bytes[p+2]
                if modrm == 0xE5:  # MOV RBP, RSP
                    print(f"  0x{addr:08X}: mov rbp, rsp")
                    p += 3
                elif modrm == 0xC1:  # MOV RAX, RCX
                    print(f"  0x{addr:08X}: mov rax, rcx")
                    p += 3
                else:
                    print(f"  0x{addr:08X}: mov [...] (modrm=0x{modrm:02X})")
                    p += 3
            elif next_byte == 0x83 and p + 3 < len(func_bytes):
                if func_bytes[p+2] == 0xEC:  # SUB RSP, imm8
                    imm = func_bytes[p+3]
                    print(f"  0x{addr:08X}: sub rsp, 0x{imm:02X}")
                    p += 4
                elif func_bytes[p+2] == 0xC4:  # TEST SPL? unlikely
                    p += 4
                else:
                    p += 1
            elif next_byte == 0xC7 and p + 6 < len(func_bytes):  # MOV [mem], imm32
                if func_bytes[p+2] == 0x84 and p + 10 < len(func_bytes):  # MOV [RSP+disp32], imm32
                    disp = struct.unpack('<I', func_bytes[p+3:p+7])[0]
                    imm = struct.unpack('<I', func_bytes[p+7:p+11])[0]
                    print(f"  0x{addr:08X}: mov [rsp+0x{disp:08X}], 0x{imm:08X}")
                    p += 11
                else:
                    p += 1
            elif next_byte == 0xB9:  # MOV RCX, imm32
                if p + 5 < len(func_bytes):
                    imm = struct.unpack('<I', func_bytes[p+2:p+6])[0]
                    print(f"  0x{addr:08X}: mov rcx, 0x{imm:08X}")
                    p += 6
                else:
                    p += 1
            else:
                p += 1
        elif byte == 0x8B and p + 2 < len(func_bytes):  # MOV reg, [mem]
            modrm = func_bytes[p+1]
            if modrm == 0x8C:  # MOV ECX, [RSP+disp32]
                if p + 5 < len(func_bytes):
                    disp = struct.unpack('<I', func_bytes[p+2:p+6])[0]
                    print(f"  0x{addr:08X}: mov ecx, [rsp+0x{disp:08X}]")
                    p += 6
                else:
                    p += 1
            else:
                print(f"  0x{addr:08X}: mov reg, [...] (modrm=0x{modrm:02X})")
                p += 1
        elif byte == 0x48 and p + 2 < len(func_bytes) and func_bytes[p+1] == 0x8D:
            if func_bytes[p+2] == 0x8C and p + 6 < len(func_bytes):  # LEA RCX, [RSP+disp32]
                disp = struct.unpack('<I', func_bytes[p+3:p+7])[0]
                print(f"  0x{addr:08X}: lea rcx, [rsp+0x{disp:08X}]")
                p += 7
            else:
                p += 1
        elif byte == 0xE9 and p + 4 < len(func_bytes):  # JMP rel32
            rel = struct.unpack('<i', func_bytes[p+1:p+5])[0]
            target = addr + 5 + rel
            print(f"  0x{addr:08X}: jmp 0x{target:08X}")
            p += 5
        elif byte == 0xEB and p + 1 < len(func_bytes):  # JMP rel8
            rel = struct.unpack('<b', func_bytes[p+1:p+2])[0]
            target = addr + 2 + rel
            print(f"  0x{addr:08X}: jmp short 0x{target:08X}")
            p += 2
        elif byte == 0x74 and p + 1 < len(func_bytes):  # JZ rel8
            rel = struct.unpack('<b', func_bytes[p+1:p+2])[0]
            target = addr + 2 + rel
            print(f"  0x{addr:08X}: jz 0x{target:08X}")
            p += 2
        elif byte == 0x0F and p + 1 < len(func_bytes) and 0x80 <= func_bytes[p+1] <= 0x8F:  # JCC rel32
            rel = struct.unpack('<i', func_bytes[p+2:p+6])[0]
            target = addr + 6 + rel
            print(f"  0x{addr:08X}: jcc 0x{target:08X}")
            p += 6
        elif byte == 0x48 and p + 1 < len(func_bytes) and func_bytes[p+1] == 0x85:  # TEST reg, reg
            if func_bytes[p+2] == 0xC9:  # TEST RCX, RCX
                print(f"  0x{addr:08X}: test rcx, rcx")
                p += 3
            else:
                p += 1
        elif byte == 0x83 and p + 2 < len(func_bytes) and func_bytes[p+1] == 0xB8:  # CMP EAX, imm8
            if func_bytes[p+2] == 0x00:
                print(f"  0x{addr:08X}: cmp eax, 0")
                p += 3
            else:
                p += 1
        elif byte == 0x33 and p + 1 < len(func_bytes) and func_bytes[p+1] == 0xC0:  # XOR EAX, EAX
            print(f"  0x{addr:08X}: xor eax, eax")
            p += 2
        elif byte == 0x55:  # PUSH RBP
            print(f"  0x{addr:08X}: push rbp")
            p += 1
        elif byte == 0x53:  # PUSH RBX
            print(f"  0x{addr:08X}: push rbx")
            p += 1
        elif byte == 0x56:  # PUSH RSI
            print(f"  0x{addr:08X}: push rsi")
            p += 1
        elif byte == 0x57:  # PUSH RDI
            print(f"  0x{addr:08X}: push rdi")
            p += 1
        elif byte == 0x41 and p + 1 < len(func_bytes) and 0x50 <= func_bytes[p+1] <= 0x57:  # PUSH R8-R15
            print(f"  0x{addr:08X}: push r{func_bytes[p+1]-0x50}")
            p += 2
        else:
            p += 1

    print("\n=== Global getters (MOV RAX, [RIP+disp32]; RET) pointing to .data ===")
    # Find all simple getters
    getter_pattern = b'\x48\x8B\x05....\xC3'
    for m in re.finditer(getter_pattern, text_data):
        pos = m.start()
        code_rva = text_rva_base + pos
        disp = struct.unpack('<i', text_data[pos+3:pos+7])[0]
        target_rva = code_rva + 7 + disp

        # Check if target is in .data
        if data_sec['rva'] <= target_rva < data_sec['rva'] + data_sec['size']:
            data_offset = target_rva - data_sec['rva']
            # Read the pointer value at that location
            if data_offset + 8 <= len(data_data):
                ptr_val = struct.unpack('<Q', data_data[data_offset:data_offset+8])[0]
                print(f"  RVA 0x{code_rva:08X}: -> 0x{target_rva:08X} (.data) *ptr = 0x{ptr_val:016X}")

    print("\n=== Global getters pointing to .rdata ===")
    rdata_sec = None
    for sec in sections:
        if sec['name'] == '.rdata':
            rdata_sec = sec
            break

    if rdata_sec:
        rdata_data = data[rdata_sec['raw']:rdata_sec['raw'] + rdata_sec['size']]
        rdata_rva_base = rdata_sec['rva']
        for m in re.finditer(getter_pattern, text_data):
            pos = m.start()
            code_rva = text_rva_base + pos
            disp = struct.unpack('<i', text_data[pos+3:pos+7])[0]
            target_rva = code_rva + 7 + disp

            if rdata_sec['rva'] <= target_rva < rdata_sec['rva'] + rdata_sec['size']:
                rdata_offset = target_rva - rdata_rva_base
                if rdata_offset + 8 <= len(rdata_data):
                    ptr_val = struct.unpack('<Q', rdata_data[rdata_offset:rdata_offset+8])[0]
                    print(f"  RVA 0x{code_rva:08X}: -> 0x{target_rva:08X} (.rdata) *ptr = 0x{ptr_val:016X}")

if __name__ == "__main__":
    main()