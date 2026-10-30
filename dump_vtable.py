import pefile
pe = pefile.PE(r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe")
image_base = pe.OPTIONAL_HEADER.ImageBase

rdata_sec = None
for s in pe.sections:
    if s.Name.decode().strip('\x00') == '.rdata':
        rdata_sec = s
        break

rdata_start = image_base + rdata_sec.VirtualAddress
rdata_data = pe.get_data(rdata_sec.PointerToRawData, rdata_sec.Misc_VirtualSize)

vtable_rva = 0x01FA0E58
vtable_va = image_base + vtable_rva
offset = vtable_va - rdata_start

with open("vtable_dump.txt", "w") as f:
    f.write(f"VTable at VA 0x{vtable_va:X} (RVA 0x{vtable_rva:X})\n")
    f.write(f"Offset in .rdata: 0x{offset:X}\n\n")

    for i in range(30):
        entry_offset = offset + i * 8
        if entry_offset + 8 <= len(rdata_data):
            entry = int.from_bytes(rdata_data[entry_offset:entry_offset+8], 'little')
            f.write(f"  [{i}] = 0x{entry:016X}\n")
            if entry != 0:
                f.write(f"      >> entry >> 8 = 0x{entry >> 8:X}\n")
                ptr = image_base + (entry >> 8)
                f.write(f"      >> VA = 0x{ptr:X}\n")
                # Check if in .text
                text_start = image_base + 0x1000
                text_end = text_start + 0x16295DF
                if text_start <= ptr < text_end:
                    f.write(f"      >> IN .text section!\n")