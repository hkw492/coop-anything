#!/usr/bin/env python3
"""
Static Binary Analysis - Option A: Find Camera Target / FollowCamera references
Search sdhdship.exe for references to "FollowCamera" or camera focus on player.
"""

import pefile
import os

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe"

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

    # Find .text section
    text_sec = None
    rdata_sec = None
    for section in pe.sections:
        name = section.Name.decode().strip('\x00')
        if name == '.text':
            text_sec = section
        elif name == '.rdata':
            rdata_sec = section

    if not text_sec:
        print("ERROR: .text section not found")
        return

    text_start = image_base + text_sec.VirtualAddress
    text_end = text_start + text_sec.Misc_VirtualSize
    text_data = pe.get_data(text_sec.PointerToRawData, text_sec.Misc_VirtualSize)

    print(f"Searching .text (VA 0x{text_start:X} - 0x{text_end:X}) for camera/player references...")
    print("=" * 100)

    # Search for string references in .rdata first
    strings_to_find = [
        b"FollowCamera",
        b"followcamera",
        b"Follow Camera",
        b"camera",
        b"Camera",
        b"LocalPlayer",
        b"localplayer",
        b"WeiShen",
        b"wei shen",
        b"Player",
        b"GetLocalPlayer",
        b"SetTarget",
        b"SetFocus",
        b"LookAt",
        b"TransformNodeComponent",
        b"SimObjectCharacter",
    ]

    if rdata_sec:
        rdata_start = image_base + rdata_sec.VirtualAddress
        rdata_data = pe.get_data(rdata_sec.PointerToRawData, rdata_sec.Misc_VirtualSize)

        print("\n--- String References in .rdata ---")
        for search_str in strings_to_find:
            offset = 0
            while True:
                idx = rdata_data.find(search_str, offset)
                if idx == -1:
                    break
                va = rdata_start + idx
                # Find xrefs to this string in .text
                print(f"\nFound string '{search_str.decode()}' at VA 0x{va:X} (RVA 0x{va - image_base:X})")

                # Search for references to this address in .text (RIP-relative or direct)
                # Look for: lea reg, [rip + disp] where target = va
                # or mov reg, imm64 where imm64 = va
                target_bytes = va.to_bytes(8, 'little')

                # Search for RIP-relative references
                for i in range(len(text_data) - 7):
                    # Check for RIP-relative LEA/MOV pattern: 48 8D 05 XX XX XX XX (lea rax, [rip+disp32])
                    if text_data[i:i+3] == b'\x48\x8d\x05' or text_data[i:i+3] == b'\x4c\x8d\x05':
                        disp = int.from_bytes(text_data[i+3:i+7], 'little', signed=True)
                        instr_addr = text_start + i
                        target = instr_addr + 7 + disp
                        if target == va:
                            print(f"  XREF: 0x{instr_addr:X} (RVA 0x{instr_addr - image_base:X}) lea reg, [rip+0x{disp:X}] -> string")
                    # Check for MOV with 32-bit displacement: 48 8B 05 XX XX XX XX (mov rax, [rip+disp32])
                    elif text_data[i:i+3] == b'\x48\x8b\x05' or text_data[i:i+3] == b'\x4c\x8b\x05':
                        disp = int.from_bytes(text_data[i+3:i+7], 'little', signed=True)
                        instr_addr = text_start + i
                        target = instr_addr + 7 + disp
                        if target == va:
                            print(f"  XREF: 0x{instr_addr:X} (RVA 0x{instr_addr - image_base:X}) mov reg, [rip+0x{disp:X}] -> string")

                offset = idx + 1

    # Search for direct string occurrences in .text (inline strings)
    print("\n--- Inline Strings in .text ---")
    for search_str in strings_to_find:
        offset = 0
        while True:
            idx = text_data.find(search_str, offset)
            if idx == -1:
                break
            va = text_start + idx
            print(f"Found '{search_str.decode()}' at VA 0x{va:X} (RVA 0x{va - image_base:X})")
            offset = idx + 1

if __name__ == "__main__":
    main()