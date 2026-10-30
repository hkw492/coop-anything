#!/usr/bin/env python3
"""
Find and dump the Simulation primary vtable to identify GetSimObject index
"""

import pefile

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe"

# Known vtables
THUNK_VTABLE_RVA = 0x01FA0E58  # 15 adjustment thunks
# Primary vtable should be nearby or referenced from the thunks

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

    # Dump thunk vtable first
    file_offset = rva_to_file_offset(pe, THUNK_VTABLE_RVA)
    if file_offset:
        data = pe.get_data(file_offset, 15 * 8)
        print(f"Thunk VTable at RVA 0x{THUNK_VTABLE_RVA:X} (VA 0x{image_base + THUNK_VTABLE_RVA:X}):")
        for i in range(15):
            entry = int.from_bytes(data[i*8:(i+1)*8], 'little')
            print(f"  [{i:2d}] 0x{entry:016X}  (RVA 0x{entry - image_base:X})")

    # Search for Simulation vtable - look for vtable with many entries pointing to code
    # The primary vtable should be in .rdata
    print("\nSearching for vtables in .rdata...")
    for section in pe.sections:
        if section.Name.decode().strip('\x00') == '.rdata':
            data = pe.get_data(section.PointerToRawData, section.Misc_VirtualSize)
            # Look for sequences of pointers that point to .text section
            text_start = image_base
            for text_sec in pe.sections:
                if text_sec.Name.decode().strip('\x00') == '.text':
                    text_start = image_base + text_sec.VirtualAddress
                    text_end = text_start + text_sec.Misc_VirtualSize
                    break

            for i in range(0, len(data) - 8*10, 8):
                # Check if this looks like a vtable (first entry often points to RTTI or destructor)
                entry0 = int.from_bytes(data[i:i+8], 'little')
                entry1 = int.from_bytes(data[i+8:i+16], 'little')

                # Both should be in .text range
                if text_start <= entry0 < text_end and text_start <= entry1 < text_end:
                    # Check a few more entries
                    valid = True
                    for j in range(min(10, (len(data)-i)//8)):
                        e = int.from_bytes(data[i+j*8:i+(j+1)*8], 'little')
                        if not (text_start <= e < text_end):
                            valid = False
                            break
                    if valid:
                        rva = section.VirtualAddress + i
                        va = image_base + rva
                        print(f"\nCandidate vtable at VA 0x{va:X} (RVA 0x{rva:X}):")
                        for j in range(min(20, (len(data)-i)//8)):
                            e = int.from_bytes(data[i+j*8:i+(j+1)*8], 'little')
                            print(f"  [{j:2d}] 0x{e:016X}  (RVA 0x{e - image_base:X})")
                        print("  ...")

if __name__ == "__main__":
    main()