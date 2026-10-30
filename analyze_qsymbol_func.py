#!/usr/bin/env python3
"""
Analyze qSymbol constructor at 0x00E95E9A and getter at 0x00184B10
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

    # Analyze function at 0x00E95E9A (CRC32 table reference)
    print("=== Function at RVA 0x00E95E9A (qSymbol constructor candidate) ===")
    rva = 0x00E95E9A
    offset = rva_to_offset(rva)
    if offset:
        func_bytes = data[offset:offset+200]
        print(f"Bytes: {func_bytes.hex()}")
        # Find function start
        func_start = rva
        for back in range(min(128, rva - text_rva_base)):
            check_rva = rva - back
            check_offset = rva_to_offset(check_rva)
            if check_offset and check_offset + 4 <= len(data):
                check_bytes = data[check_offset:check_offset+4]
                if check_bytes[0] == 0x48 and check_bytes[1] == 0x83 and check_bytes[2] == 0xEC:
                    func_start = check_rva
                    break
                if check_bytes[0] == 0x55 and check_bytes[1] == 0x48 and check_bytes[2] == 0x8B and check_bytes[3] == 0xEC:
                    func_start = check_rva
                    break
                if check_bytes[0] == 0x53 and check_offset + 3 < len(data):
                    next_b = data[check_offset+1:check_offset+4]
                    if next_b[0] == 0x48 and next_b[1] == 0x83 and next_b[2] == 0xEC:
                        func_start = check_rva
                        break
        if func_start != rva:
            print(f"Function starts at RVA 0x{func_start:08X}")
            func_offset = rva_to_offset(func_start)
            if func_offset:
                func_bytes = data[func_offset:func_offset+200]
                print(f"Full function bytes: {func_bytes.hex()}")
                # Disassemble
                p = 0
                while p < min(150, len(func_bytes)):
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
                        if next_byte == 0x8D and p + 2 < len(func_bytes):
                            modrm = func_bytes[p+2]
                            if modrm == 0x3D and p + 6 < len(func_bytes):  # LEA RDI, [RIP+disp32]
                                disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                                target = addr + 7 + disp
                                print(f"  0x{addr:08X}: lea rdi, [rip+0x{disp:08X}] -> 0x{target:08X}")
                                p += 7
                            elif modrm == 0x35 and p + 6 < len(func_bytes):  # LEA RSI, [RIP+disp32]
                                disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                                target = addr + 7 + disp
                                print(f"  0x{addr:08X}: lea rsi, [rip+0x{disp:08X}] -> 0x{target:08X}")
                                p += 7
                            elif modrm == 0x0D and p + 6 < len(func_bytes):  # LEA RCX, [RIP+disp32]
                                disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                                target = addr + 7 + disp
                                print(f"  0x{addr:08X}: lea rcx, [rip+0x{disp:08X}] -> 0x{target:08X}")
                                p += 7
                            elif modrm == 0x15 and p + 6 < len(func_bytes):  # LEA RDX, [RIP+disp32]
                                disp = struct_unpack('<i', func_bytes[p+3:p+7])[0]
                                target = addr + 7 + disp
                                print(f"  0x{addr:08X}: lea rdx, [rip+0x{disp:08X}] -> 0x{target:08X}")
                                p += 7
                            else:
                                p += 1
                        elif next_byte == 0x8B and p + 2 < len(func_bytes):
                            modrm = func_bytes[p+2]
                            if modrm == 0x05 and p + 6 < len(func_bytes):  # MOV RAX, [RIP+disp32]
                                disp = struct.unpack('<i', func_bytes[p+3:p+7])[0]
                                target = addr + 7 + disp
                                print(f"  0x{addr:08X}: mov rax, [rip+0x{disp:08X}] -> 0x{target:08X}")
                                p += 7
                            elif modrm == 0xC1:  # MOV RAX, RCX
                                print(f"  0x{addr:08X}: mov rax, rcx")
                                p += 3
                            elif modrm == 0x01:  # MOV RAX, [RCX]
                                print(f"  0x{addr:08X}: mov rax, [rcx]")
                                p += 3
                            else:
                                p += 1
                        elif next_byte == 0x85 and p + 2 < len(func_bytes):
                            if func_bytes[p+2] == 0xC9:  # TEST RCX, RCX
                                print(f"  0x{addr:08X}: test rcx, rcx")
                                p += 3
                            elif func_bytes[p+2] == 0xFF:  # TEST RDI, RDI
                                print(f"  0x{addr:08X}: test rdi, rdi")
                                p += 3
                            else:
                                p += 1
                        elif next_byte == 0x83 and p + 3 < len(func_bytes):
                            if func_bytes[p+2] == 0xEC:  # SUB RSP, imm8
                                imm = func_bytes[p+3]
                                print(f"  0x{addr:08X}: sub rsp, 0x{imm:02X}")
                                p += 4
                            elif func_bytes[p+2] == 0xF9:  # CMP RCX, imm8
                                imm = func_bytes[p+3]
                                print(f"  0x{addr:08X}: cmp rcx, 0x{imm:02X}")
                                p += 4
                            else:
                                p += 1
                        else:
                            p += 1
                    elif byte == 0x85 and p + 1 < len(func_bytes):
                        if func_bytes[p+1] == 0xC9:  # TEST RCX, RCX
                            print(f"  0x{addr:08X}: test rcx, rcx")
                            p += 2
                        elif func_bytes[p+1] == 0xFF:  # TEST RDI, RDI
                            print(f"  0x{addr:08X}: test rdi, rdi")
                            p += 2
                        else:
                            p += 1
                    elif byte == 0x74 and p + 1 < len(func_bytes):  # JZ rel8
                        rel = struct.unpack('<b', func_bytes[p+1:p+2])[0]
                        target = addr + 2 + rel
                        print(f"  0x{addr:08X}: jz 0x{target:08X}")
                        p += 2
                    elif byte == 0x75 and p + 1 < len(func_bytes):  # JNZ rel8
                        rel = struct.unpack('<b', func_bytes[p+1:p+2])[0]
                        target = addr + 2 + rel
                        print(f"  0x{addr:08X}: jnz 0x{target:08X}")
                        p += 2
                    elif byte == 0x0F and p + 1 < len(func_bytes) and 0x80 <= func_bytes[p+1] <= 0x8F:
                        if p + 5 < len(func_bytes):
                            rel = struct.unpack('<i', func_bytes[p+2:p+6])[0]
                            target = addr + 6 + rel
                            print(f"  0x{addr:08X}: jcc 0x{target:08X}")
                            p += 6
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
                    elif byte == 0x48 and p + 1 < len(func_bytes):
                        if func_bytes[p+1] == 0x03 and p + 2 < len(func_bytes):  # ADD
                            p += 1
                        elif func_bytes[p+1] == 0x83 and p + 3 < len(func_bytes):
                            p += 1
                        else:
                            p += 1
                    elif byte == 0x8A and p + 1 < len(func_bytes):  # MOV AL, [reg]
                        print(f"  0x{addr:08X}: mov al, [reg]")
                        p += 2
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
                    elif byte == 0x41 and p + 1 < len(func_bytes) and 0x50 <= func_bytes[p+1] <= 0x57:
                        print(f"  0x{addr:08X}: push r{func_bytes[p+1]-0x50}")
                        p += 2
                    else:
                        p += 1

    # Analyze getter at 0x00184B10
    print("\n=== Getter at RVA 0x00184B10 ===")
    rva = 0x00184B10
    offset = rva_to_offset(rva)
    if offset:
        func_bytes = data[offset:offset+100]
        print(f"Bytes: {func_bytes.hex()}")
        # First function: MOV RAX, [RIP+disp32]; RET
        if func_bytes[0:3] == b'\x48\x8B\x05':
            disp = struct.unpack('<i', func_bytes[3:7])[0]
            target = rva + 7 + disp
            print(f"  Function 1: MOV RAX, [RIP+0x{disp:08X}] -> 0x{target:08X}")
            print(f"  RET at offset 7")
            # Second function starts after padding (0xCC bytes)
            # Find first non-0xCC byte after offset 7
            p = 8
            while p < len(func_bytes) and func_bytes[p] == 0xCC:
                p += 1
            if p < len(func_bytes):
                second_rva = rva + p
                print(f"  Function 2 starts at RVA 0x{second_rva:08X} (offset {p})")
                second_bytes = func_bytes[p:p+80]
                print(f"  Bytes: {second_bytes.hex()}")
                # Disassemble second function
                p2 = 0
                while p2 < min(80, len(second_bytes)):
                    byte = second_bytes[p2]
                    addr = second_rva + p2
                    if byte == 0xC3:
                        print(f"  0x{addr:08X}: ret")
                        break
                    elif byte == 0x40 and p2 + 1 < len(second_bytes):
                        if second_bytes[p2+1] == 0x57:  # PUSH RDI
                            print(f"  0x{addr:08X}: push rdi")
                            p2 += 2
                        else:
                            p2 += 1
                    elif byte == 0x48 and p2 + 1 < len(second_bytes):
                        next_byte = second_bytes[p2+1]
                        if next_byte == 0x83 and p2 + 3 < len(second_bytes):
                            if second_bytes[p2+2] == 0xEC:  # SUB RSP, imm8
                                imm = second_bytes[p2+3]
                                print(f"  0x{addr:08X}: sub rsp, 0x{imm:02X}")
                                p2 += 4
                            else:
                                p2 += 1
                        elif next_byte == 0x89 and p2 + 2 < len(second_bytes):
                            if second_bytes[p2+2] == 0x5C and p2 + 6 < len(second_bytes):  # MOV [RSP+...], RBX
                                print(f"  0x{addr:08X}: mov [rsp+...], rbx")
                                p2 += 7
                            elif second_bytes[p2+2] == 0xE5:  # MOV RBP, RSP
                                print(f"  0x{addr:08X}: mov rbp, rsp")
                                p2 += 3
                            else:
                                p2 += 1
                        elif next_byte == 0x8B and p2 + 2 < len(second_bytes):
                            modrm = second_bytes[p2+2]
                            if modrm == 0x05 and p2 + 6 < len(second_bytes):
                                disp = struct.unpack('<i', second_bytes[p2+3:p2+7])[0]
                                target = addr + 7 + disp
                                print(f"  0x{addr:08X}: mov rax, [rip+0x{disp:08X}] -> 0x{target:08X}")
                                p2 += 7
                            elif modrm == 0x0D:  # MOV RCX, [RCX]
                                print(f"  0x{addr:08X}: mov rcx, [rcx]")
                                p2 += 3
                            elif modrm == 0xC1:  # MOV RAX, RCX
                                print(f"  0x{addr:08X}: mov rax, rcx")
                                p2 += 3
                            else:
                                p2 += 1
                        else:
                            p2 += 1
                    elif byte == 0x8B and p2 + 1 < len(second_bytes):
                        if second_bytes[p2+1] == 0x05 and p2 + 5 < len(second_bytes):  # MOV EAX, [RIP+disp32]
                            disp = struct.unpack('<i', second_bytes[p2+2:p2+6])[0]
                            target = addr + 6 + disp
                            print(f"  0x{addr:08X}: mov eax, [rip+0x{disp:08X}] -> 0x{target:08X}")
                            p2 += 6
                        else:
                            p2 += 1
                    elif byte == 0xA8:  # TEST AL, imm8
                        if p2 + 1 < len(second_bytes):
                            imm = second_bytes[p2+1]
                            print(f"  0x{addr:08X}: test al, 0x{imm:02X}")
                            p2 += 2
                        else:
                            p2 += 1
                    elif byte == 0x75:  # JNZ rel8
                        if p2 + 1 < len(second_bytes):
                            rel = struct.unpack('<b', second_bytes[p2+1:p2+2])[0]
                            target = addr + 2 + rel
                            print(f"  0x{addr:08X}: jnz 0x{target:08X}")
                            p2 += 2
                        else:
                            p2 += 1
                    elif byte == 0x83 and p2 + 1 < len(second_bytes):
                        if second_bytes[p2+1] == 0xC8:  # OR EAX, imm8
                            if p2 + 2 < len(second_bytes):
                                imm = second_bytes[p2+2]
                                print(f"  0x{addr:08X}: or eax, 0x{imm:02X}")
                                p2 += 3
                            else:
                                p2 += 1
                        elif second_bytes[p2+1] == 0x0D:  # OR [RIP+disp32], imm8
                            p2 += 1
                        else:
                            p2 += 1
                    elif byte == 0x89 and p2 + 1 < len(second_bytes):
                        if second_bytes[p2+1] == 0x05 and p2 + 5 < len(second_bytes):  # MOV [RIP+disp32], EAX
                            disp = struct.unpack('<i', second_bytes[p2+2:p2+6])[0]
                            target = addr + 6 + disp
                            print(f"  0x{addr:08X}: mov [rip+0x{disp:08X}], eax -> 0x{target:08X}")
                            p2 += 6
                        else:
                            p2 += 1
                    else:
                        p2 += 1

    # Check what .data 0x02039CD0 contains
    print("\n=== .data at RVA 0x02039CD0 (getter 0x00184B10 target) ===")
    target_rva = 0x02039CD0
    data_offset = target_rva - data_rva_base
    if 0 <= data_offset < len(data_data) - 8:
        ptr = struct.unpack('<Q', data_data[data_offset:data_offset+8])[0]
        print(f"  .data RVA 0x{target_rva:08X} contains: 0x{ptr:016X}")
        # Check if it's a heap pointer
        if 0x0000000100000000 <= ptr <= 0x00007FFFFFFFFFFF:
            print(f"  -> Heap pointer!")
            # Check vtable
            if 0x140000000 <= ptr < 0x142000000:
                print(f"  -> Vtable in module range (.rdata)")

if __name__ == "__main__":
    main()