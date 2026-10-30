#!/usr/bin/env python3
"""
Search for string literals "Player" and "WeiShen" in the binary
"""

import pefile

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe"

def search_section(pe, section, search_bytes, name):
    data = pe.get_data(section.PointerToRawData, section.Misc_VirtualSize)

    idx = 0
    while True:
        idx = data.find(search_bytes, idx)
        if idx == -1:
            break
        rva = section.VirtualAddress + idx
        va = pe.OPTIONAL_HEADER.ImageBase + rva
        print(f"  Found '{name}' at VA 0x{va:016X} (RVA 0x{rva:X}) in section {section.Name.decode().strip()}")
        idx += 1

def main():
    pe = pefile.PE(EXE_PATH)

    print(f"Searching for string literals:")

    for section in pe.sections:
        sec_name = section.Name.decode().strip('\x00')
        if sec_name in ['.text', '.rdata', '.data']:
            search_section(pe, section, b"Player", "Player")
            search_section(pe, section, b"WeiShen", "WeiShen")
            search_section(pe, section, b"Wei Shen", "Wei Shen")
            search_section(pe, section, b"getsimobject", "getsimobject")
            search_section(pe, section, b"GetSimObject", "GetSimObject")

if __name__ == "__main__":
    main()