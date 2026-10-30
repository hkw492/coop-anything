#!/usr/bin/env python3
"""
Search for calls to Simulation thunk (0xC55270) and subsequent stores to GameState+0x20
"""

import pefile

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe"
SIM_THUNK_RVA = 0x00C55270
SIM_THUNK_VA = 0x140C55270

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

    # Search .text section for CALL to 0x140C55270
    text_section = None
    for section in pe.sections:
        if section.Name.decode().strip('\x00') == '.text':
            text_section = section
            break

    if not text_section:
        print("No .text section found")
        return

    data = pe.get_data(text_section.PointerToRawData, text_section.Misc_VirtualSize)

    # Search for CALL rel32 to 0x140C55270
    # E8 xx xx xx xx = call rel32
    # Target = next_ip + rel32
    # rel32 = target - next_ip

    target_va = SIM_THUNK_VA

    for i in range(len(data) - 5):
        if data[i] == 0xE8:  # CALL rel32
            rel32 = int.from_bytes(data[i+1:i+5], 'little', signed=True)
            next_ip = image_base + text_section.VirtualAddress + i + 5
            call_target = next_ip + rel32

            if call_target == target_va:
                rva = text_section.VirtualAddress + i
                va = image_base + rva
                print(f"Found CALL to Simulation thunk at VA 0x{va:X} (RVA 0x{rva:X})")

                # Check following instructions for store to [rcx+0x20] or similar
                # Print next 20 bytes
                print(f"  Following bytes: {' '.join(f'{b:02x}' for b in data[i:i+30])}")

if __name__ == "__main__":
    main()