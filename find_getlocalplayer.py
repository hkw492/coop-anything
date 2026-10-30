#!/usr/bin/env python3
"""
Find GetLocalPlayer function in sdhdship.exe
Scans for strings, patterns, and function signatures related to local player retrieval.
"""

import mmap
import struct
import sys
import re
from pathlib import Path

EXE_PATH = Path(r"C:\HK\COOP\coop-anything\local\sleeping-dogs-test\sdhdship.exe")

def read_exe():
    with open(EXE_PATH, "rb") as f:
        return mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

def find_strings(data, min_len=4):
    """Extract ASCII strings from binary data."""
    results = []
    current = bytearray()
    offset = 0
    for byte in data:
        b = byte if isinstance(byte, int) else byte[0]
        if 32 <= b <= 126:  # printable ASCII
            current.append(b)
        else:
            if len(current) >= min_len:
                results.append((offset - len(current), current.decode('ascii', errors='ignore')))
            current = bytearray()
        offset += 1
    if len(current) >= min_len:
        results.append((offset - len(current), current.decode('ascii', errors='ignore')))
    return results

def find_unicode_strings(data, min_len=4):
    """Extract UTF-16LE strings from binary data."""
    results = []
    # Look for UTF-16LE strings (every other byte is 0)
    for i in range(0, len(data) - min_len * 2, 2):
        try:
            s = data[i:i + min_len * 2].decode('utf-16le', errors='strict')
            if all(32 <= ord(c) <= 126 for c in s):
                # Extend the string
                j = i + min_len * 2
                while j + 1 < len(data) and data[j + 1] == 0 and 32 <= data[j] <= 126:
                    j += 2
                full = data[i:j].decode('utf-16le')
                results.append((i, full))
        except UnicodeDecodeError:
            pass
    return results

def search_pattern(data, pattern):
    """Search for a byte pattern with wildcards (??)"""
    # Convert pattern like "48 8B ?? 89" to regex
    parts = pattern.split()
    regex_parts = []
    for p in parts:
        if p == "??":
            regex_parts.append(b".")
        else:
            regex_parts.append(bytes.fromhex(p))
    regex = b"".join(regex_parts)
    matches = []
    for m in re.finditer(regex, data):
        matches.append(m.start())
    return matches

def rva_to_offset(data, rva):
    """Convert RVA to file offset (simplified - assumes standard PE layout)"""
    # Parse PE header to get section mapping
    if data[:2] != b'MZ':
        return None
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    if pe_offset + 4 > len(data) or data[pe_offset:pe_offset+4] != b'PE\0\0':
        return None

    # COFF header
    num_sections = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
    opt_header_size = struct.unpack('<H', data[pe_offset+20:pe_offset+22])[0]
    sections_start = pe_offset + 24 + opt_header_size

    # Find section containing RVA
    for i in range(num_sections):
        sec = sections_start + i * 40
        if sec + 40 > len(data):
            break
        sec_rva = struct.unpack('<I', data[sec+12:sec+16])[0]
        sec_size = struct.unpack('<I', data[sec+16:sec+20])[0]
        sec_raw = struct.unpack('<I', data[sec+20:sec+24])[0]

        if sec_rva <= rva < sec_rva + sec_size:
            return sec_raw + (rva - sec_rva)
    return None

def main():
    print(f"Scanning {EXE_PATH} ({EXE_PATH.stat().st_size:,} bytes)")
    data = read_exe()

    # 1. Search for relevant strings
    print("\n=== Searching for relevant strings ===")
    strings = find_strings(data)
    keywords = [
        "LocalPlayer", "localplayer", "GetLocalPlayer", "getlocalplayer",
        "PlayerController", "playercontroller", "SimObjectCharacter",
        "SimObject", "character", "WeiShen", "Wei Shen",
        "Player", "player", "Controller", "controller",
        "UFG::", "Ufg::", "ufg::"
    ]

    for offset, s in strings:
        for kw in keywords:
            if kw.lower() in s.lower():
                rva = offset  # approximation
                print(f"  0x{rva:08X} (file): {s}")
                break

    # 2. Search Unicode strings
    print("\n=== Searching Unicode strings ===")
    ustrings = find_unicode_strings(data)
    for offset, s in ustrings:
        for kw in keywords:
            if kw.lower() in s.lower():
                print(f"  0x{offset:08X} (file): {s}")
                break

    # 3. Search for function patterns
    print("\n=== Searching for function patterns ===")

    # Common x64 function prologues
    patterns = [
        # GetLocalPlayer might be: mov rax, [global_ptr]; ret
        ("48 8B 05 ?? ?? ?? ?? C3", "mov rax, [rip+offset] / ret - simple getter"),
        # Or: mov rax, gs:[offset] ; ret  (thread-local)
        ("65 48 8B 04 25 ?? ?? ?? ?? C3", "mov rax, gs:[offset] / ret"),
        # Function that takes controller index and returns SimObjectCharacter*
        ("48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 48 8B DA 8B F1", "standard prologue with rbx, rsi, rdi"),
        # Look for vtable calls - virtual function calls
        ("FF 15 ?? ?? ?? ??", "call [rip+offset] - indirect call"),
    ]

    for pattern, desc in patterns:
        matches = search_pattern(data, pattern)
        if matches:
            print(f"  Pattern: {pattern} ({desc})")
            for m in matches[:10]:  # Show first 10
                print(f"    0x{m:08X}")
            if len(matches) > 10:
                print(f"    ... and {len(matches) - 10} more")

    # 4. Search for specific SDmodding SDK patterns
    print("\n=== Searching for SDmodding SDK patterns ===")
    # The SDK uses RVA 0x209E170 for local player pointer
    # Let's check what's at that RVA
    rva = 0x209E170
    offset = rva_to_offset(data, rva)
    if offset and offset + 8 <= len(data):
        val = struct.unpack('<Q', data[offset:offset+8])[0]
        print(f"  RVA 0x{rva:08X} (file offset 0x{offset:08X}): 0x{val:016X}")
        if val != 0:
            print(f"    -> Points to: 0x{val:016X}")

    # 5. Search for "SimObjectCharacter" vtable or type info
    print("\n=== Searching for SimObjectCharacter references ===")
    for kw in ["SimObjectCharacter", "CharacterPhysicsComponent", "TransformNodeComponent"]:
        matches = [m.start() for m in re.finditer(kw.encode('ascii'), data)]
        if matches:
            print(f"  '{kw}' found at {len(matches)} locations:")
            for m in matches[:5]:
                print(f"    0x{m:08X}")

    # 6. Look for cross-references to the global player pointer area
    print("\n=== Searching for references to player pointer area ===")
    # Search for instructions that reference around 0x209E170
    target_rva = 0x209E170
    # RIP-relative addressing: lea rax, [rip+offset] where offset = target - (next_instruction)
    # We'll search for the 32-bit offset value
    for base_rva in range(0x1000000, 0x3000000, 0x1000):
        offset = rva_to_offset(data, base_rva)
        if not offset or offset + 4 > len(data):
            continue
        # This is a simplified search - in reality we'd need full disassembly

    data.close()

if __name__ == "__main__":
    main()