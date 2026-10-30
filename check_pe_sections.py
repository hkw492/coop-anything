#!/usr/bin/env python3
"""
Check PE sections and vtable entry addresses
"""

import struct
from pathlib import Path

EXE_PATH = Path(r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe")

def main():
    with open(EXE_PATH, "rb") as f:
        data = f.read()

    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    print(f"PE offset: 0x{pe_offset:X}")

    # COFF header
    machine = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
    num_sections = struct.unpack('<H', data[pe_offset+6:pe_offset+8])[0]
    print(f"Machine: 0x{machine:X}, Sections: {num_sections}")

    # Optional header
    opt_header_magic = struct.unpack('<H', data[pe_offset+24:pe_offset+26])[0]
    print(f"Optional header magic: 0x{opt_header_magic:X} (PE32+ = 0x20B)")

    image_base = struct.unpack('<Q', data[pe_offset+48:pe_offset+56])[0]
    print(f"ImageBase: 0x{image_base:016X}")

    section_alignment = struct.unpack('<I', data[pe_offset+56:pe_offset+60])[0]
    file_alignment = struct.unpack('<I', data[pe_offset+60:pe_offset+64])[0]
    print(f"SectionAlignment: 0x{section_alignment:X}, FileAlignment: 0x{file_alignment:X}")

    size_of_image = struct.unpack('<I', data[pe_offset+80:pe_offset+84])[0]
    size_of_headers = struct.unpack('<I', data[pe_offset+84:pe_offset+88])[0]
    print(f"SizeOfImage: 0x{size_of_image:X}, SizeOfHeaders: 0x{size_of_headers:X}")

    opt_header_size = struct.unpack('<H', data[pe_offset+20:pe_offset+22])[0]
    print(f"Optional header size: {opt_header_size}")
    sections_start = pe_offset + 24 + opt_header_size
    print(f"Sections start at file offset: 0x{sections_start:X}")

    sections = []
    for i in range(num_sections):
        sec = sections_start + i * 40
        name = data[sec:sec+8].rstrip(b'\0').decode('ascii', errors='ignore')
        virtual_size = struct.unpack('<I', data[sec+8:sec+12])[0]
        virtual_address = struct.unpack('<I', data[sec+12:sec+16])[0]
        size_of_raw_data = struct.unpack('<I', data[sec+16:sec+20])[0]
        pointer_to_raw_data = struct.unpack('<I', data[sec+20:sec+24])[0]
        characteristics = struct.unpack('<I', data[sec+24:sec+28])[0]
        sections.append({
            'name': name,
            'virtual_size': virtual_size,
            'virtual_address': virtual_address,
            'size_of_raw_data': size_of_raw_data,
            'pointer_to_raw_data': pointer_to_raw_data,
            'characteristics': characteristics
        })
        print(f"\n  Section {i}: {name}")
        print(f"    VirtualAddress: 0x{virtual_address:08X}")
        print(f"    VirtualSize: 0x{virtual_size:08X}")
        print(f"    SizeOfRawData: 0x{size_of_raw_data:08X}")
        print(f"    PointerToRawData: 0x{pointer_to_raw_data:08X}")
        print(f"    Characteristics: 0x{characteristics:08X}")
        print(f"    VA range: 0x{image_base + virtual_address:016X} - 0x{image_base + virtual_address + virtual_size:016X}")

    # Check the vtable entry value 0x143048C
    vtable_entry = 0x143048C
    print(f"\n=== Vtable entry analysis ===")
    print(f"Vtable entry value: 0x{vtable_entry:X}")
    print(f"As RVA: 0x{vtable_entry:X}")
    print(f"As VA (ImageBase + RVA): 0x{image_base + vtable_entry:016X}")

    # Check if it falls in any section
    for sec in sections:
        sec_va_start = image_base + sec['virtual_address']
        sec_va_end = sec_va_start + sec['virtual_size']
        if sec_va_start <= image_base + vtable_entry < sec_va_end:
            print(f"  Falls in section {sec['name']} at VA offset 0x{(image_base + vtable_entry) - sec_va_start:X}")
        # Also check as RVA
        if sec['virtual_address'] <= vtable_entry < sec['virtual_address'] + sec['virtual_size']:
            print(f"  Falls in section {sec['name']} at RVA offset 0x{vtable_entry - sec['virtual_address']:X}")

    # Check the actual .text section size in file
    text_sec = next(s for s in sections if s['name'] == '.text')
    print(f"\n=== .text section details ===")
    print(f"  VirtualAddress: 0x{text_sec['virtual_address']:08X}")
    print(f"  VirtualSize: 0x{text_sec['virtual_size']:08X}")
    print(f"  SizeOfRawData: 0x{text_sec['size_of_raw_data']:08X}")
    print(f"  PointerToRawData: 0x{text_sec['pointer_to_raw_data']:08X}")

    # Read the actual .text data size
    text_raw_start = text_sec['pointer_to_raw_data']
    text_raw_end = text_raw_start + text_sec['size_of_raw_data']
    print(f"  File range: 0x{text_raw_start:X} - 0x{text_raw_end:X}")
    print(f"  Actual file size: {len(data)}")

    # The vtable entry 0x143048C as RVA
    # .text RVA range: 0x1000 to 0x1000 + 0x1629600 = 0x162A600
    # 0x143048C > 0x162A600, so it's outside .text
    # But wait, the vtable entry was printed as 0x000000000143048C (64-bit)
    # Let me check the actual bytes in the vtable

if __name__ == "__main__":
    main()