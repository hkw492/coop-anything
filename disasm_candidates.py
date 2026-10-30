import mmap
import struct
import re
from pathlib import Path

EXE_PATH = Path(r"C:\HK\COOP\coop-anything\local\sleeping-dogs-test\sdhdship.exe")

def read_exe():
    with open(EXE_PATH, "rb") as f:
        return mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

def rva_to_offset(data, rva):
    if data[:2] != b'MZ': return None
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    if data[pe_offset:pe_offset+4] != b'PE\0\0': return None
    num_sections = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
    opt_header_size = struct.unpack('<H', data[pe_offset+20:pe_offset+22])[0]
    sections_start = pe_offset + 24 + opt_header_size
    for i in range(num_sections):
        sec = sections_start + i * 40
        sec_rva = struct.unpack('<I', data[sec+12:sec+16])[0]
        sec_size = struct.unpack('<I', data[sec+16:sec+20])[0]
        sec_raw = struct.unpack('<I', data[sec+20:sec+24])[0]
        if sec_rva <= rva < sec_rva + sec_size:
            return sec_raw + (rva - sec_rva)
    return None

def get_rva_from_offset(data, offset):
    if data[:2] != b'MZ': return None
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    if data[pe_offset:pe_offset+4] != b'PE\0\0': return None
    num_sections = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
    opt_header_size = struct.unpack('<H', data[pe_offset+20:pe_offset+22])[0]
    sections_start = pe_offset + 24 + opt_header_size
    for i in range(num_sections):
        sec = sections_start + i * 40
        sec_raw = struct.unpack('<I', data[sec+20:sec+24])[0]
        sec_rva = struct.unpack('<I', data[sec+12:sec+16])[0]
        sec_size = struct.unpack('<I', data[sec+16:sec+20])[0]
        if sec_raw <= offset < sec_raw + sec_size:
            return sec_rva + (offset - sec_raw)
    return None

data = read_exe()

# Get section info
pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
num_sections = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
opt_header_size = struct.unpack('<H', data[pe_offset+20:pe_offset+22])[0]
sections_start = pe_offset + 24 + opt_header_size

text_rva = text_raw = text_size = 0
for i in range(num_sections):
    sec = sections_start + i * 40
    name = data[sec:sec+8].rstrip(b'\0').decode('ascii', errors='ignore')
    sec_rva = struct.unpack('<I', data[sec+12:sec+16])[0]
    sec_size = struct.unpack('<I', data[sec+16:sec+20])[0]
    sec_raw = struct.unpack('<I', data[sec+20:sec+24])[0]
    if name == '.text':
        text_rva, text_raw, text_size = sec_rva, sec_raw, sec_size

# Search for MOV RAX, [RCX*8 + disp32] = 48 8B 04 CD disp32
pattern = b'\x48\x8B\x04\xCD'
candidates = []
for m in re.finditer(pattern, data):
    pos = m.start()
    if text_raw <= pos < text_raw + text_size:
        if pos + 8 <= len(data):
            disp = struct.unpack('<i', data[pos+4:pos+8])[0]
            func_rva = get_rva_from_offset(data, pos)
            if func_rva:
                candidates.append((func_rva, pos, disp))

# Take first 15 and disassemble them fully
for func_rva, pos, disp in candidates[:15]:
    func_offset = rva_to_offset(data, func_rva)
    if func_offset:
        print(f'\n=== Function at RVA 0x{func_rva:08X} (file 0x{func_offset:08X}) ===')
        print(f'  Array access at offset 0x{pos:08X}: disp=0x{disp:08X} ({disp})')
        # Disassemble from function start
        for back in range(func_offset, max(text_raw, func_offset-16), -1):
            if back >= 3 and (data[back] == 0x48 and data[back+1] == 0x89 and data[back+2] in (0x5C, 0x74, 0x7C)):
                func_offset = back
                break
            if back >= 1 and data[back] == 0x55:
                func_offset = back
                break
        # Disassemble forward
        p = func_offset
        for _ in range(30):
            if p >= len(data): break
            byte = data[p]
            if byte == 0xC3:
                print(f'  0x{get_rva_from_offset(data, p):08X}: ret')
                break
            elif byte == 0xC2 and p+2 < len(data):
                imm = struct.unpack('<H', data[p+1:p+3])[0]
                print(f'  0x{get_rva_from_offset(data, p):08X}: ret 0x{imm:04X}')
                break
            elif byte == 0xE8 and p+4 < len(data):
                rel = struct.unpack('<i', data[p+1:p+5])[0]
                target = p + 5 + rel
                print(f'  0x{get_rva_from_offset(data, p):08X}: call 0x{get_rva_from_offset(data, target):08X}')
                p += 5
            elif byte == 0x48 and p+1 < len(data) and data[p+1] == 0x8B:
                if p+6 < len(data) and data[p+2] == 0x05:
                    disp2 = struct.unpack('<i', data[p+3:p+7])[0]
                    target = p + 7 + disp2
                    print(f'  0x{get_rva_from_offset(data, p):08X}: mov rax, [rip+0x{disp2:08X}] -> 0x{get_rva_from_offset(data, target):08X}')
                    p += 7
                elif p+3 < len(data):
                    modrm = data[p+2]
                    if (modrm & 0xC7) == 0x04:
                        if p+7 < len(data):
                            sib = data[p+3]
                            disp2 = struct.unpack('<i', data[p+4:p+8])[0]
                            index = (sib >> 3) & 0x7
                            scale = (sib >> 6) & 0x3
                            scale_val = 1 << scale
                            regs = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi']
                            index_str = f'{regs[index]}*{scale_val}' if index != 4 else ''
                            base_str = regs[sib & 0x7]
                            if sib & 0x7 == 5 and (modrm >> 6) == 0:
                                addr = f'[rip+{index_str}+0x{disp2:X}]' if index_str else f'[rip+0x{disp2:X}]'
                            else:
                                addr = f'[{base_str}+{index_str}+0x{disp2:X}]' if index_str else f'[{base_str}+0x{disp2:X}]'
                            print(f'  0x{get_rva_from_offset(data, p):08X}: mov rax, {addr}')
                            p += 8
                        else:
                            p += 3
                    else:
                        p += 3
                else:
                    p += 3
            elif byte == 0x48 and p+2 < len(data) and data[p+1] == 0x83 and data[p+2] == 0xF9:
                if p+3 < len(data):
                    imm = data[p+3]
                    print(f'  0x{get_rva_from_offset(data, p):08X}: cmp rcx, 0x{imm:02X}')
                    p += 4
            elif byte == 0x85 and p+1 < len(data) and data[p+1] == 0xC9:
                print(f'  0x{get_rva_from_offset(data, p):08X}: test ecx, ecx')
                p += 2
            elif byte >= 0x70 and byte <= 0x7F:
                if p+1 < len(data):
                    rel = struct.unpack('<b', data[p+1:p+2])[0]
                    target = p + 2 + rel
                    print(f'  0x{get_rva_from_offset(data, p):08X}: jcc 0x{get_rva_from_offset(data, target):08X}')
                    p += 2
            elif byte == 0x0F and p+1 < len(data) and 0x80 <= data[p+1] <= 0x8F:
                if p+5 < len(data):
                    rel = struct.unpack('<i', data[p+2:p+6])[0]
                    target = p + 6 + rel
                    print(f'  0x{get_rva_from_offset(data, p):08X}: jcc 0x{get_rva_from_offset(data, target):08X}')
                    p += 6
            else:
                p += 1

data.close()