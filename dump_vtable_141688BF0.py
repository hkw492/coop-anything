#!/usr/bin/env python3
"""
Dump the vtable at 0x141688BF0 (from Simulation thunk)
"""

import pefile

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe"

VTABLE_VA = 0x141688BF0

def rva_to_file_offset(pe, rva):
    for section in pe.sections:
        sec_start = section.VirtualAddress
        sec_end = section.VirtualAddress + section.Misc_VirtualSize
        if sec_start <= rva < sec_end:
            return (rva - sec_start) + section.PointerToRawData
    return None

def main():
    pe = pefile.PE(EXE_PATH)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    rva = VTABLE_VA - image_base
    file_offset = rva_to_file_offset(pe, rva)

    if file_offset is None:
        print(f"ERROR: VA 0x{VTABLE_VA:X} not found")
        # Try reading raw
        for section in pe.sections:
            sec_start = image_base + section.VirtualAddress
            sec_end = sec_start + section.Misc_VirtualSize
            if sec_start <= VTABLE_VA < sec_end:
                offset = (VTABLE_VA - sec_start) + section.PointerToRawData
                data = pe.get_data(offset, 30 * 8)
                print(f"Found in section {section.Name.decode().strip()} at file offset 0x{offset:X}")
                for i in range(30):
                    entry = int.from_bytes(data[i*8:(i+1)*8], 'little')
                    text_sec = None
                    for ts in pe.sections:
                        if ts.Name.decode().strip('\x00') == '.text':
                            text_sec = ts
                            break
                    text_start = image_base + text_sec.VirtualAddress if text_sec else 0
                    text_end = text_start + text_sec.Misc_VirtualSize if text_sec else 0
                    in_text = " >>> IN .text <<<" if text_start <= entry < text_end else ""
                    print(f"  [{i:2d}] 0x{entry:016X}  (RVA 0x{entry - image_base:X}){in_text}")
                return
        return

    data = pe.get_data(file_offset, 30 * 8)
    print(f"VTable at VA 0x{VTABLE_VA:X} (RVA 0x{rva:X}):")
    for i in range(30):
        entry = int.from_bytes(data[i*8:(i+1)*8], 'little')
        text_sec = None
        for ts in pe.sections:
            if ts.Name.decode().strip('\x00') == '.text':
                text_sec = ts
                break
        text_start = image_base + text_sec.VirtualAddress if text_sec else 0
        text_end = text_start + text_sec.Misc_VirtualSize if text_sec else 0
        in_text = " >>> IN .text <<<" if text_start <= entry < text_end else ""
        print(f"  [{i:2d}] 0x{entry:016X}  (RVA 0x{entry - image_base:X}){in_text}")

if __name__ == "__main__":
    main()