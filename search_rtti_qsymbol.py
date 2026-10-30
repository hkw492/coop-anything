#!/usr/bin/env python3
"""
Static Binary Analysis - Option B: RTTI Cross-References
Search for RTTI CompleteObjectLocator for:
- SimObjectCharacter
- TransformNodeComponent
Find code xrefs that assign/access the player instance.
"""

import pefile

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe"

# Known qSymbol hashes (CRC32)
QSYMBOL_PLAYER = 0x9FB57F53
QSYMBOL_WEISHEN = 0x9AF96AFB

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

    # Find sections
    text_sec = None
    rdata_sec = None
    data_sec = None
    for section in pe.sections:
        name = section.Name.decode().strip('\x00')
        if name == '.text':
            text_sec = section
        elif name == '.rdata':
            rdata_sec = section
        elif name == '.data':
            data_sec = section

    if not text_sec:
        print("ERROR: .text section not found")
        return

    text_start = image_base + text_sec.VirtualAddress
    text_end = text_start + text_sec.Misc_VirtualSize
    text_data = pe.get_data(text_sec.PointerToRawData, text_sec.Misc_VirtualSize)

    print(f"Searching .text (VA 0x{text_start:X} - 0x{text_end:X})")
    print("=" * 100)

    # Search for qSymbol hashes (4-byte values) in .text
    print("\n--- qSymbol Hash References in .text ---")
    for name, hash_val in [("Player", QSYMBOL_PLAYER), ("WeiShen", QSYMBOL_WEISHEN)]:
        hash_bytes = hash_val.to_bytes(4, 'little')
        offset = 0
        while True:
            idx = text_data.find(hash_bytes, offset)
            if idx == -1:
                break
            va = text_start + idx
            print(f"  {name} hash (0x{hash_val:08X}) at VA 0x{va:X} (RVA 0x{va - image_base:X})")
            # Show context (10 bytes before/after)
            ctx_start = max(0, idx - 10)
            ctx_end = min(len(text_data), idx + 4 + 10)
            ctx = text_data[ctx_start:ctx_end]
            print(f"    Context: {' '.join(f'{b:02x}' for b in ctx)}")
            offset = idx + 1

    # Search for RTTI structures in .rdata
    if rdata_sec:
        rdata_start = image_base + rdata_sec.VirtualAddress
        rdata_data = pe.get_data(rdata_sec.PointerToRawData, rdata_sec.Misc_VirtualSize)

        print("\n--- RTTI Type Descriptors in .rdata ---")
        # RTTI TypeDescriptor typically starts with:
        # - vptr to type_info vtable
        # - spare
        # - name (mangled)
        # Look for mangled names like ".?AVSimObjectCharacter@UFG@@"
        rtti_strings = [
            b".?AVSimObjectCharacter@UFG@@",
            b".?AVTransformNodeComponent@UFG@@",
            b".?AVSimObject@UFG@@",
            b".?AVComponent@UFG@@",
            b"SimObjectCharacter",
            b"TransformNodeComponent",
        ]

        for search_str in rtti_strings:
            offset = 0
            while True:
                idx = rdata_data.find(search_str, offset)
                if idx == -1:
                    break
                va = rdata_start + idx
                print(f"\n  Found RTTI string '{search_str.decode()}' at VA 0x{va:X} (RVA 0x{va - image_base:X})")

                # Find xrefs in .text
                target_bytes = va.to_bytes(8, 'little')
                # Search for RIP-relative references
                for i in range(len(text_data) - 7):
                    # lea reg, [rip+disp32] - 48 8D 05 / 4C 8D 05
                    if text_data[i:i+3] in (b'\x48\x8d\x05', b'\x4c\x8d\x05'):
                        disp = int.from_bytes(text_data[i+3:i+7], 'little', signed=True)
                        instr_addr = text_start + i
                        target = instr_addr + 7 + disp
                        if target == va:
                            print(f"    XREF: 0x{instr_addr:X} lea reg, [rip+0x{disp:X}]")
                    # mov reg, [rip+disp32] - 48 8B 05 / 4C 8B 05
                    elif text_data[i:i+3] in (b'\x48\x8b\x05', b'\x4c\x8b\x05'):
                        disp = int.from_bytes(text_data[i+3:i+7], 'little', signed=True)
                        instr_addr = text_start + i
                        target = instr_addr + 7 + disp
                        if target == va:
                            print(f"    XREF: 0x{instr_addr:X} mov reg, [rip+0x{disp:X}]")

                offset = idx + 1

    # Search for CompleteObjectLocator pattern (vptr, offset, cdOffset, typeDescriptor, classDescriptor)
    if rdata_sec:
        print("\n--- CompleteObjectLocator Candidates in .rdata ---")
        for i in range(0, len(rdata_data) - 20, 8):
            # First entry should be a vptr (points to type_info vtable in .rdata/.text)
            # Second entry = offset (usually 0)
            # Third entry = cdOffset (usually -1 or 0)
            # Fourth entry = TypeDescriptor pointer
            # Fifth entry = ClassDescriptor pointer
            pass  # Too complex for quick search

    # Search for qSymbol hash references in .rdata/.data
    if rdata_sec:
        print("\n--- qSymbol Hash References in .rdata ---")
        for name, hash_val in [("Player", QSYMBOL_PLAYER), ("WeiShen", QSYMBOL_WEISHEN)]:
            hash_bytes = hash_val.to_bytes(4, 'little')
            offset = 0
            while True:
                idx = rdata_data.find(hash_bytes, offset)
                if idx == -1:
                    break
                va = rdata_start + idx
                print(f"  {name} hash (0x{hash_val:08X}) at VA 0x{va:X} (RVA 0x{va - image_base:X})")
                offset = idx + 1

    if data_sec:
        data_start = image_base + data_sec.VirtualAddress
        data_data = pe.get_data(data_sec.PointerToRawData, data_sec.Misc_VirtualSize)

        print("\n--- qSymbol Hash References in .data ---")
        for name, hash_val in [("Player", QSYMBOL_PLAYER), ("WeiShen", QSYMBOL_WEISHEN)]:
            hash_bytes = hash_val.to_bytes(4, 'little')
            offset = 0
            while True:
                idx = data_data.find(hash_bytes, offset)
                if idx == -1:
                    break
                va = data_start + idx
                print(f"  {name} hash (0x{hash_val:08X}) at VA 0x{va:X} (RVA 0x{va - image_base:X})")
                offset = idx + 1

if __name__ == "__main__":
    main()