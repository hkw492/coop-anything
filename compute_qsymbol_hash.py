#!/usr/bin/env python3
"""
Find RIP-relative references to CRC32 table and compute qSymbol hashes
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

    text_sec = None
    rdata_sec = None
    for sec in sections:
        if sec['name'] == '.text':
            text_sec = sec
        elif sec['name'] == '.rdata':
            rdata_sec = sec

    text_data = data[text_sec['raw']:text_sec['raw'] + text_sec['size']]
    text_rva_base = text_sec['rva']
    rdata_data = data[rdata_sec['raw']:rdata_sec['raw'] + rdata_sec['size']]
    rdata_rva_base = rdata_sec['rva']

    # CRC32 table at RVA 0x01AC14C0
    crc_table_rva = 0x01AC14C0

    # Search for RIP-relative references: lea reg, [rip+disp32] where target = crc_table_rva
    # LEA RSI, [RIP+disp32] = 48 8D 35 disp32
    # LEA RDI, [RIP+disp32] = 48 8D 3D disp32
    # LEA RCX, [RIP+disp32] = 48 8D 0D disp32
    # LEA RDX, [RIP+disp32] = 48 8D 15 disp32
    # LEA R8, [RIP+disp32] = 4C 8D 05 disp32
    # LEA R9, [RIP+disp32] = 4C 8D 0D disp32
    # MOV RSI, [RIP+disp32] = 48 8B 35 disp32
    # MOV RDI, [RIP+disp32] = 48 8B 3D disp32
    # MOV RCX, [RIP+disp32] = 48 8B 0D disp32

    print("=== Searching for RIP-relative references to CRC32 table ===")
    lea_patterns = [
        (b'\x48\x8D\x35', 'lea rsi'),
        (b'\x48\x8D\x3D', 'lea rdi'),
        (b'\x48\x8D\x0D', 'lea rcx'),
        (b'\x48\x8D\x15', 'lea rdx'),
        (b'\x4C\x8D\x05', 'lea r8'),
        (b'\x4C\x8D\x0D', 'lea r9'),
        (b'\x48\x8B\x35', 'mov rsi'),
        (b'\x48\x8B\x3D', 'mov rdi'),
        (b'\x48\x8B\x0D', 'mov rcx'),
        (b'\x48\x8B\x15', 'mov rdx'),
    ]

    for pattern, name in lea_patterns:
        for m in re.finditer(pattern, text_data):
            pos = m.start()
            code_rva = text_rva_base + pos
            if pos + 6 < len(text_data):
                disp = struct.unpack('<i', text_data[pos+3:pos+7])[0]
                target_rva = code_rva + 7 + disp
                if target_rva == crc_table_rva:
                    print(f"  RVA 0x{code_rva:08X}: {name} [rip+0x{disp:08X}] -> CRC32 table")
                    # Show function context
                    func_start = code_rva
                    for back in range(min(128, pos)):
                        check_pos = pos - back
                        if check_pos >= 0:
                            b = text_data[check_pos]
                            if b == 0x48 and check_pos + 2 < len(text_data):
                                if text_data[check_pos+1] == 0x83 and text_data[check_pos+2] == 0xEC:
                                    func_start = text_rva_base + check_pos
                                    break
                                if text_data[check_pos+1] == 0x89 and text_data[check_pos+2] == 0xE5:
                                    func_start = text_rva_base + check_pos
                                    break
                            if b == 0x55 and check_pos + 3 < len(text_data):
                                if text_data[check_pos+1] == 0x48 and text_data[check_pos+2] == 0x8B and text_data[check_pos+3] == 0xEC:
                                    func_start = text_rva_base + check_pos
                                    break
                            if b == 0x53 and check_pos + 3 < len(text_data):
                                if text_data[check_pos+1] == 0x48 and text_data[check_pos+2] == 0x83 and text_data[check_pos+3] == 0xEC:
                                    func_start = text_rva_base + check_pos
                                    break
                    if func_start != code_rva:
                        func_offset = rva_to_offset(func_start)
                        if func_offset:
                            func_bytes = data[func_offset:func_offset+120]
                            print(f"    Function at RVA 0x{func_start:08X}:")
                            print(f"    {func_bytes[:80].hex()}")

    # Also search for direct absolute references (mov reg, imm64) - unlikely for CRC table
    print("\n=== Computing qSymbol hash for 'Player' and 'WeiShen' ===")
    # UFG qSymbol uses CRC32 with polynomial 0xEDB88320 (standard)
    # Initial value: 0xFFFFFFFF, Final XOR: 0xFFFFFFFF, Reflect input/output: True
    # This is standard CRC32 (ISO 3309 / PKZIP)

    import binascii

    def crc32_ufg(s):
        """Compute UFG qSymbol hash (CRC32)"""
        # Standard CRC32
        crc = binascii.crc32(s.encode('ascii')) & 0xFFFFFFFF
        return crc

    player_hash = crc32_ufg("Player")
    weishen_hash = crc32_ufg("WeiShen")
    print(f"  Player: 0x{player_hash:08X} ({player_hash})")
    print(f"  WeiShen: 0x{weishen_hash:08X} ({weishen_hash})")

    # Also try with different initial/final values
    # Some implementations use initial 0, final 0
    def crc32_custom(s, init=0xFFFFFFFF, xorout=0xFFFFFFFF, reflect=True):
        crc = init
        for c in s.encode('ascii'):
            if reflect:
                c = int('{:08b}'.format(c)[::-1], 2)
            crc ^= c << 24
            for _ in range(8):
                if crc & 0x80000000:
                    crc = (crc << 1) ^ 0x04C11DB7
                else:
                    crc = crc << 1
                crc &= 0xFFFFFFFF
        if reflect:
            crc = int('{:032b}'.format(crc)[::-1], 2)
        return crc ^ xorout

    print("\n  Trying different CRC32 variants:")
    for init in [0xFFFFFFFF, 0]:
        for xorout in [0xFFFFFFFF, 0]:
            for reflect in [True, False]:
                h1 = crc32_custom("Player", init, xorout, reflect)
                h2 = crc32_custom("WeiShen", init, xorout, reflect)
                print(f"    init={init:08X} xorout={xorout:08X} reflect={reflect}: Player=0x{h1:08X} WeiShen=0x{h2:08X}")

    # Also check the global getter at 0x00184B10 which looked different
    print("\n=== Analyzing getter at 0x00184B10 ===")
    getter_rva = 0x00184B10
    offset = rva_to_offset(getter_rva)
    if offset:
        func_bytes = data[offset:offset+64]
        print(f"  Bytes: {func_bytes.hex()}")
        # Disassemble
        p = 0
        while p < min(50, len(func_bytes)):
            byte = func_bytes[p]
            addr = getter_rva + p
            if byte == 0xC3:
                print(f"  0x{addr:08X}: ret")
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
                    elif modrm == 0xC1:
                        print(f"  0x{addr:08X}: mov rax, rcx")
                        p += 3
                    else:
                        p += 1
                elif next_byte == 0xC7:
                    p += 1
                elif next_byte == 0x83:
                    p += 1
                else:
                    p += 1
            elif byte == 0x40 and p + 1 < len(func_bytes):
                if func_bytes[p+1] == 0x57:  # push rdi
                    print(f"  0x{addr:08X}: push rdi")
                    p += 2
                else:
                    p += 1
            elif byte == 0x48 and p + 1 < len(func_bytes) and func_bytes[p+1] == 0x83:
                p += 1
            else:
                p += 1

if __name__ == "__main__":
    main()