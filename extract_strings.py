import mmap
import re

with open(r'C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe', 'rb') as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    content = mm.read()
    mm.close()

# Find printable strings
strings = re.findall(b'[\x20-\x7e]{4,}', content)
keywords = ['unreal', 'cryengine', 'havok', 'engine', 'steam', 'network', 'replication', 'lobby', 'matchmaking', 'physx', 'fmod', 'wwise', 'scaleform', 'directx', 'd3d', 'dxgi', 'gamebryo', 'unity', 'ue4', 'ue5', 'rage', 'source', 'id tech', 'bullet', 'awesomium', 'cef', 'chromium', 'steamworks', 'steam_api', 'steamclient', 'steamnetworking', 'p2p', 'relay', 'natpunch', 'upnp', 'stun', 'turn', 'ice', 'dtls', 'srtp', 'webrtc', 'openssl', 'mbedtls', 'wolfssl']

found = set()
for s in strings:
    s = s.decode('ascii', errors='ignore')
    s_lower = s.lower()
    for kw in keywords:
        if kw in s_lower:
            found.add(s[:200])
            break

for f in sorted(found):
    print(f)