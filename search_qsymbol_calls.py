#!/usr/bin/env python3
"""
Search for qSymbol hash constants (Player=0x9FB57F53, WeiShen=0x9AF96AFB)
in the code to find where GetSimObject is called.
"""

import pefile

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe"

# qSymbol hashes we're looking for
PLAYER_HASH = 0x9FB57F53
WEISHEN_HASH = 0x9AF96AFB

def rva_to_file_offset(pe, rva):
    for section in pe.sections:
        sec_start = section.VirtualAddress
        sec_end = section.VirtualAddress + section.Misc_VirtualSize
        if sec_start <= rva < sec_end:
            return (rva - sec_start) + section.PointerToRawData
    return None

def search_section(pe, section, hash_val, name):
    sec_start = section.VirtualAddress
    sec_end = section.VirtualAddress + section.Misc_VirtualSize
    data = pe.get_data(section.PointerToRawData, section.Misc_VirtualSize)

    # Search for 4-byte little-endian hash
    hash_bytes = hash_val.to_bytes(4, 'little')
    offset = 0
    while True:
        idx = data.find(hash_bytes, offset)
        if idx == -1:
            break
        rva = sec_start + idx
        va = pe.OPTIONAL_HEADER.ImageBase + rva
        print(f"  Found {name} hash 0x{hash_val:08X} at VA 0x{va:016X} (RVA 0x{rva:X}) in section {section.Name.decode().strip()}")
        offset = idx + 1

def main():
    pe = pefile.PE(EXE_PATH)

    print(f"Searching for qSymbol hashes:")
    print(f"  Player: 0x{PLAYER_HASH:08X}")
    print(f"  WeiShen: 0x{WEISHEN_HASH:08X}")
    print()

    for section in pe.sections:
        name = section.Name.decode().strip('\x00')
        if name in ['.text', '.rdata', '.data']:
            search_section(pe, section, PLAYER_HASH, "Player")
            search_section(pe, section, WEISHEN_HASH, "WeiShen")

if __name__ == "__main__":
    main()