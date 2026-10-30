#!/usr/bin/env python3
"""
Check PE sections to find where RVA 0xE28510 and 0xE28610 are located
"""

import pefile

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe"

pe = pefile.PE(EXE_PATH)

print("Sections:")
for section in pe.sections:
    name = section.Name.decode().strip('\x00')
    va_start = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
    va_end = va_start + section.Misc_VirtualSize
    print(f"  {name}: VA 0x{va_start:X} - 0x{va_end:X} (RVA 0x{section.VirtualAddress:X} - 0x{section.VirtualAddress + section.Misc_VirtualSize:X}, Size: 0x{section.Misc_VirtualSize:X})")

# Check specific RVAs
for rva in [0xE284D0, 0xE28510, 0xE28610]:
    found = False
    for section in pe.sections:
        sec_start = section.VirtualAddress
        sec_end = section.VirtualAddress + section.Misc_VirtualSize
        if sec_start <= rva < sec_end:
            print(f"\nRVA 0x{rva:X} is in section {section.Name.decode().strip()}")
            print(f"  File offset: 0x{(rva - sec_start) + section.PointerToRawData:X}")
            found = True
            break
    if not found:
        print(f"\nRVA 0x{rva:X} NOT FOUND in any section!")