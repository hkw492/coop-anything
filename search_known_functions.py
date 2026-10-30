#!/usr/bin/env python3
"""
Search for known function patterns:
1. GetLocalPlayer at RVA 0x8CD060 - trace its calls
2. Camera update functions
3. Minimap/HUD GPS coordinate queries
"""

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe"

KNOWN_FUNCTIONS = {
    0x008CD060: "GetLocalPlayer(int)",
    0x00E28480: "GameState::OnUpdate",
    0x00E2C240: "GameState::OnEnter",
    0x004614ED: "GameState+0x20 init",
    0x00C55270: "Simulation thunk",
    0x00152250: "SimGetter1",
    0x00152260: "SimGetter2",
    0x00152270: "SimGetter3",
    0x00152280: "SimGetter4",
    0x00152290: "SimGetter5",
}

def rva_to_file_offset(pe, rva):
    for section in pe.sections:
        sec_start = section.VirtualAddress
        sec_end = section.VirtualAddress + section.Misc_VirtualSize
        if sec_start <= rva < sec_end:
            return (rva - sec_start) + section.PointerToRawData
    return None

def disasm_at(pe, image_base, rva, max_insns=50):
    file_offset = rva_to_file_offset(pe, rva)
    if file_offset is None:
        return []
    code_bytes = pe.get_data(file_offset, 200)
    va = image_base + rva

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    insns = []
    for insn in md.disasm(code_bytes, va):
        insns.append(insn)
        if len(insns) >= max_insns:
            break
        if insn.mnemonic == 'ret':
            break
    return insns

def main():
    pe = pefile.PE(EXE_PATH)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    # Find .text section
    text_sec = None
    for section in pe.sections:
        if section.Name.decode().strip('\x00') == '.text':
            text_sec = section
            break

    text_start = image_base + text_sec.VirtualAddress
    text_end = text_start + text_sec.Misc_VirtualSize
    text_data = pe.get_data(text_sec.PointerToRawData, text_sec.Misc_VirtualSize)

    print("=" * 100)
    print("DISASSEMBLY OF KNOWN FUNCTIONS")
    print("=" * 100)

    # Disassemble GetLocalPlayer
    print(f"\n=== GetLocalPlayer at RVA 0x008CD060 ===")
    for insn in disasm_at(pe, image_base, 0x008CD060, 30):
        bytes_str = " ".join(f"{b:02x}" for b in insn.bytes)
        print(f"0x{insn.address:016X}  {bytes_str:<32}  {insn.mnemonic} {insn.op_str}")

    # Disassemble SimGetter1
    print(f"\n=== SimGetter1 at RVA 0x00152250 ===")
    for insn in disasm_at(pe, image_base, 0x00152250, 20):
        bytes_str = " ".join(f"{b:02x}" for b in insn.bytes)
        print(f"0x{insn.address:016X}  {bytes_str:<32}  {insn.mnemonic} {insn.op_str}")

    # Disassemble SimGetter2
    print(f"\n=== SimGetter2 at RVA 0x00152260 ===")
    for insn in disasm_at(pe, image_base, 0x00152260, 20):
        bytes_str = " ".join(f"{b:02x}" for b in insn.bytes)
        print(f"0x{insn.address:016X}  {bytes_str:<32}  {insn.mnemonic} {insn.op_str}")

    # Search for CALL instructions to GetLocalPlayer
    print(f"\n=== XREFs to GetLocalPlayer (0x1408CD060) ===")
    target_va = image_base + 0x008CD060
    target_rel = (target_va - 0x140000000).to_bytes(4, 'little', signed=True)  # 32-bit relative

    # Search for CALL rel32 (E8 XX XX XX XX) to GetLocalPlayer
    for i in range(len(text_data) - 5):
        if text_data[i] == 0xE8:  # CALL rel32
            disp = int.from_bytes(text_data[i+1:i+5], 'little', signed=True)
            instr_va = text_start + i
            call_target = instr_va + 5 + disp
            if call_target == target_va:
                print(f"  CALL at 0x{instr_va:X} (RVA 0x{instr_va - image_base:X})")

    # Search for RIP-relative references to GetLocalPlayer
    target_bytes = target_va.to_bytes(8, 'little')
    print(f"\n=== RIP-relative XREFs to GetLocalPlayer ===")
    for i in range(len(text_data) - 7):
        # lea reg, [rip+disp32] - 48 8D 05 / 4C 8D 05
        if text_data[i:i+3] in (b'\x48\x8d\x05', b'\x4c\x8d\x05'):
            disp = int.from_bytes(text_data[i+3:i+7], 'little', signed=True)
            instr_addr = text_start + i
            target = instr_addr + 7 + disp
            if target == target_va:
                print(f"  lea at 0x{instr_addr:X} (RVA 0x{instr_addr - image_base:X})")
        # mov reg, [rip+disp32] - 48 8B 05 / 4C 8B 05
        elif text_data[i:i+3] in (b'\x48\x8b\x05', b'\x4c\x8b\x05'):
            disp = int.from_bytes(text_data[i+3:i+7], 'little', signed=True)
            instr_addr = text_start + i
            target = instr_addr + 7 + disp
            if target == target_va:
                print(f"  mov at 0x{instr_addr:X} (RVA 0x{instr_addr - image_base:X})")

    # Search for "camera" related strings in entire binary
    print(f"\n=== Searching for 'camera' in all sections ===")
    for section in pe.sections:
        name = section.Name.decode().strip('\x00')
        data = pe.get_data(section.PointerToRawData, section.Misc_VirtualSize)
        sec_start = image_base + section.VirtualAddress

        for search in [b"camera", b"Camera", b"CAMERA", b"Follow", b"follow", b"Focus", b"focus", b"Target", b"target"]:
            offset = 0
            while True:
                idx = data.find(search, offset)
                if idx == -1:
                    break
                va = sec_start + idx
                print(f"  Found '{search.decode()}' in {name} at VA 0x{va:X} (RVA 0x{va - image_base:X})")
                offset = idx + 1

if __name__ == "__main__":
    main()