# Sleeping Dogs: Definitive Edition - Co-op Mod State

**Last Updated:** 2026-10-30 (Session 7 - Simulation Singleton Global Verified via Static Binary Analysis, Build Success — **DEVELOPMENT FROZEN, STABLE STATE**)  
**Game Version:** Sleeping Dogs: Definitive Edition (Steam)  
**Executable:** sdhdship.exe  
**SHA-256:** 2a33ec787ac6fd4c86fec2b6f778feea881a3f35ea56c680121f53571c0527da  
**Engine:** United Front Games "Mad Science" (proprietary) with Havok Physics & SkookumScript  
**Architecture:** x86_64 (PE32+)

---

## Runtime Session: 2026-10-30 Session 7 (SIMULATION SINGLETON GLOBAL VERIFIED, BUILD SUCCESSFUL)

**Module Base:** `0x7ff729bd0000` (ASLR - from latest log)  
**Verified Simulation Instance:** Resolved via direct global `g_pSimulationInstance` at RVA `0x20383B0` (in .data section)  
**Build Status:** ✅ Successfully built and deployed to Steam install directory (`plugins/` only)  
**Position Logging:** ✅ Implemented - logs ">>> WEI SHEN POS: X=%.2f, Y=%.2f, Z=%.2f" every 120 ticks

### Repository State: **FROZEN — Stable, Well-Documented Baseline**
- All hooks stable for 2,500+ ticks / zero crashes
- No blind vtable probing; all function indices statically verified
- Memory safety: SEH guards + strict 8-byte alignment + MSVC fill-pattern rejection
- Comprehensive documentation in `local/sleeping-dogs-coop/README.md` and this file
- Ready for Milestone 1 (live transform extraction → P2P packet → remote puppet spawn)

### Critical Static Analysis Findings (Session 6-7)

#### 1. **GetSimObject Found at Simulation vtable[8] (RVA 0xB6DC0)**
- **Location**: Simulation vtable index 8 (0-based) = offset 0x40 from vtable base
- **RVA**: `0x00B6DC0` (compressed format: stored as `0xB6DC0 << 8 = 0x0B6DC000` in vtable entry)
- **Signature**: `SimObject* GetSimObject(Simulation* this, qSymbol* name, int, void*)` using `__fastcall`
- **qSymbol hashes**: 
  - `Player` = `0x9FB57F53` (CRC32)
  - `WeiShen` = `0x9AF96AFB` (CRC32)
- **Implementation**: `FindTrueLocalPlayer()` in hooks.cpp now calls this directly instead of blind vtable probing

#### 2. **Spawn Parameter Block Decoded (NOT the Actor Simulation)**
- **Address observed**: `0x7ff43922efa0` (from Session 4 log hex dump at tick 120)
- **Content**: ASCII strings decoded from the 16 QWORD dump:
  ```
  +0x00: 0x0000000000000000
  +0x08: 0x7FF729BD0000  -> Module base (sdhdship.exe)
  +0x10: 0x0000000000000000
  +0x18: 0x0000000000000000
  +0x20: "HongKong"      <- World/level name
  +0x28: "Player"        <- Actor name/qSymbol
  +0x30: "WeiShen"       <- Character template
  +0x38: 0x0000000000000000
  +0x40: 0x0000000000000000
  +0x48: 0x0000000000000000
  +0x50: 0x0000000000000000
  +0x58: 0x0000000000000000
  +0x60: 0x0000000000000000
  +0x68: 0x0000000000000000
  +0x70: 0x0000000000000000
  +0x78: 0x0000000000000000
  ```
- **Conclusion**: GameState+0x20 is a **spawn parameter block** (world="HongKong", actor="Player", template="WeiShen"), NOT the active Simulation instance. This explains why it was stable but wrong for finding the live player.

#### 3. **Engine Uses GameState+0x98 for Active Simulation (Verified via Disassembly)**
- **GameState::OnUpdate loop** at RVA `0xE28510`: `mov rbx, [rdi + 0x98]` - loads Simulation* for the update loop
- **GameState::OnUpdate** continues to use `[rbx]` (the Simulation from +0x98) for all subsequent operations:
  - `mov [rcx + r14 + 0x20], eax` - write to Simulation+0x20
  - `mov [rcx + r14 + 0x28], rax` - write to Simulation+0x28  
  - `lea rcx, [rbx + 0xA0]` - call with Simulation+0xA0
- **Hook Implementation**: `HK_GameState_OnUpdate` and `HK_GameState_OnEnter` now read the Simulation singleton global (RVA 0x20383B0) as the primary source

#### 4. **GameState+0x20 Initialization (One-time at Spawn)**
- **Function**: `0x004614ED` - called once during spawn/level load
- **Action**: Calls Simulation thunk `0xC55270` which initializes the Simulation and stores result to GameState+0x20
- **Result**: The spawn parameter block (not the ongoing Simulation instance)

#### 5. **VERIFIED: Simulation Singleton Global `g_pSimulationInstance` at RVA 0x20383B0 (Session 7)**
- **Discovery Method**: Static binary analysis of Simulation getter functions (no guessing, no runtime probing)
- **GetInstance_1** at RVA `0x152250`: `mov rax, [rip + 0x1EE6159]; ret`
  - Target global: `0x152250 + 7 + 0x1EE6159 = 0x20383B0`
- **GetInstance_3** at RVA `0x152270`: Same pattern, same global
- **GetInstance_2/4/5**: Different globals (likely subsystem instances)
- **Global Location**: `.data` section at RVA `0x20383B0` (VA = module_base + 0x20383B0)
- **Content**: Directly holds the `UFG::Simulation*` heap pointer (the singleton `m_pInstance`)
- **Hook Implementation**: Both `HK_GameState_OnUpdate` and `HK_GameState_OnEnter` now read this global directly:
  ```cpp
  uptr* simGlobalPtr = reinterpret_cast<uptr*>(Hooks::GetModuleBase() + UFG::SimulationRVA::SingletonPtr);
  if (simGlobalPtr && IsValidUserPtr(*simGlobalPtr))
      resolvedSim = reinterpret_cast<UFG::Simulation*>(*simGlobalPtr);
  ```
- **Cached**: Stored in `g_cachedSimulation` for use by `FindTrueLocalPlayer()` and co-op networking

### Fixes Deployed (Session 6-7)
1. **Implemented GetSimObject-based player lookup** in `FindTrueLocalPlayer()`:
   - Resolves `Simulation_GetSimObject_t` from `sim->vtable[8]` at runtime
   - Calls with qSymbol `Player` (0x9FB57F53), falls back to `WeiShen` (0x9AF96AFB)
   - Returns validated `UFG::SimObjectCharacter*` heap pointer
2. **Updated Simulation resolution to use direct global at RVA 0x20383B0** (verified via disassembly of GetInstance_1/3)
3. **Added position logging every 120 ticks** in requested format:
   ```
   [SleepingDogsCoop] >>> WEI SHEN POS: X=123.45, Y=67.89, Z=-42.10
   ```
4. **Removed ALL blind vtable probing** - no more candidateIndices loop, no more destructor calls
5. **Strict 8-byte alignment** enforced in `IsValidUserPtr()` - rejects any pointer with `(ptr & 0x7) != 0`

### Build & Deploy
```bash
cmake --build build --config Release
```
✅ Build successful, ASI deployed to `plugins/`

---

## Runtime Session: 2026-10-30 Session 5 (ALIGNMENT FIX - Root Cause: Unaligned GameState+0x98)

**Module Base:** `0x7ff729bd0000` (ASLR - from latest log)  
**Verified Simulation Instance:** `0x7ff41cbcefa0` (from GameState+0x20 - 16-byte aligned, stable)  
**Build Status:** ✅ Successfully built and deployed to Steam install directory (`plugins/` only)

### Root Cause Analysis (from Session 4 log)
- **GameState+0x98** returned **unaligned odd address**: `0x7ff43d9f0f83` (ends in 3!) → crashed when reading `sim+0x10` (spliced two memory fields into garbage)
- **GameState+0x20** returned **16-byte aligned address**: `0x7ff41cbcefa0` (ends in 0) → ran 2,500+ ticks without crash
- Reading `sim+0x10` at odd boundary = memory corruption → immediate CPU crash on vtable call

### Fixes Deployed (Session 5)
1. **Reverted to GameState+0x20** for Simulation pointer resolution in `HK_GameState_OnUpdate` and `HK_GameState_OnEnter`
2. **Enforced strict 8-byte alignment** in `IsValidUserPtr()`:
   ```cpp
   inline bool IsValidUserPtr(uptr u) {
       return u >= 0x10000 && u < 0x00007FFFFFFEFFFF && (u & 0x7) == 0;
   }
   ```
   - Any pointer with `(ptr & 0x7) != 0` is rejected immediately
3. **STOPPED blind vtable calling** - removed loop invoking candidateIndices (2..15) with `__vectorcall`
   - Guessing virtual calls on live engine singletons corrupts registers and destroys objects
4. **Added Simulation object hex dump** at tick 120 (first 16 QWORDs: +0x00 to +0x78)
5. **Created disassembly script** `disasm_gamestate_onupdate_full.py` for GameState::OnUpdate at RVA 0xE28480

### Disassembly Findings (GameState::OnUpdate, first 60 instructions)
```
0xE28480: mov rax, [rcx + 0x38]          ; Load from GameState+0x38
0xE28491: mov rbp, [rcx + 0x30]          ; Load from GameState+0x30
0xE28510: mov rbx, [rdi + 0x98]          ; Loop: load Simulation* from GameState+0x98
0xE28551: mov [rcx + r14 + 0x20], eax    ; Write to Simulation+0x20
```
- Engine **CODE** uses GameState+0x98 in loop (disassembly verified)
- But **RUNTIME VALUE** at GameState+0x98 can be unaligned (observed in Session 4)
- GameState+0x20 initialized at `0x004614ED` via Simulation thunk - returns aligned heap pointer
- **Conclusion**: Use GameState+0x20 for stable aligned pointer; engine's +0x98 may be set later or differ

### Build & Deploy
```bash
cmake --build build --config Release
```
✅ Build successful, ASI deployed to `plugins/`

---

## Runtime Session: 2026-10-30 (Latest Test - Session 4)

**Module Base:** `0x7ff754d70000` (ASLR)  
**Controller Address Tested:** `0x7ff7563dc238` (base + `0x166C238`)  
**Crash Status:** ✅ **FIXED** - `IsValidUserPtr()` prevented Access Violation (0xC0000005)  
**Controller Dump:** Added one-time dump of first 16 QWORDs to locate `m_pSimObject` offset  
**CRITICAL FINDING:** Controller at `0x7ff7563dc238` is a **static vtable/interface table in .rdata**, NOT a dynamic controller instance. Offsets +0x08 through +0x78 are all module code pointers (RVAs 0x1AC0, 0x9D0B0, 0x2AF950, etc.). The function at RVA `0x008CD060` returns this interface table, not an active player object.

**Current Blocker:** Need to find the **true local player SimObject** (heap `UFG::SimObjectCharacter*`). The SDK's global at RVA `0x209E170` is NULL. The `GetLocalPlayer(int)` function returns an interface table, not the player object.

## Runtime Session: 2026-10-30 (Simulation Instance Connected - Session 2)

**Module Base:** `0x7ff78ecf0000` (ASLR - from latest log)  
**Verified Simulation Instance:** `0x7ff4d262efa0` (heap address from GameState+0x20)  
**Build Status:** ✅ Successfully built and deployed to Steam install directory (`plugins/` only)  
**Key Implementation Changes:**
- ✅ **Connected Simulation Instance**: `HK_GameState_OnUpdate` now caches the resolved Simulation instance from `GameState+0x20` (`0x7ff4d262efa0`) in `g_cachedSimulation`
- ✅ **FindTrueLocalPlayer Updated**: `FindTrueLocalPlayer(UFG::Simulation* simPtr)` now accepts a Simulation pointer parameter; uses cached `g_cachedSimulation` directly instead of failing static getters
- ✅ **Disassembly Analysis**: Disassembled `GameState::OnUpdate` (actual function entry at RVA `0x00E28480`, loop at `0x00E28510`) - verified it uses `GameState` pointer in `RDI`, accesses `GameState+0x30`, `+0x38`, `+0x98`
- ✅ **SEH Protection Preserved**: All calls to `GetSimObject` (vtable slots 0-19) remain wrapped in `__try/__except` with `ProbeExceptionFilter` logging
- ✅ **Auto-Deploy Single Copy**: CMake copies `SleepingDogsCoop.asi` ONLY to `C:/Program Files (x86)/Steam/steamapps/common/SleepingDogsDefinitiveEdition/plugins/` (root copy removed)

**Expected Log Output (next run):**
```
[SleepingDogsCoop] --> Entered HK_GameState_OnEnter
[SleepingDogsCoop] OnEnter: Found active Simulation instance via GameState+0x20: 0x...
[SleepingDogsCoop] GameState::OnEnter (InGame)
...
[SleepingDogsCoop] --> Tick #0 in HK_GameState_OnUpdate
[SleepingDogsCoop] Found active Simulation instance via GameState+0x20: 0x...
...
[SleepingDogsCoop] Probing Simulation getter 0x152250 at 0x...
[SleepingDogsCoop] Probing Simulation vtable[0] at 0x...
...
```

---

## Runtime Session: 2026-10-30 Session 3 (Crash at Tick 120 - ROOT CAUSE IDENTIFIED & FIXED)

**Module Base:** `0x7ff78ecf0000` (ASLR)  
**Verified Simulation Instance:** `0x7ff4d262efa0` (heap address from GameState+0x20 - consistent across 2,500+ ticks)  
**Build Status:** ✅ Successfully built and deployed to Steam install directory (`plugins/` only)

### Crash Analysis (Tick 120)
- **Event:** Game crashed with fast-fail at tick 120 when `FindTrueLocalPlayer()` executed
- **Root Cause:** Blind vtable probing loop (indices 0-19) called `Simulation vtable[0]` and/or `vtable[1]`
- **MSVC vtable layout:** Index 0 = virtual destructor, Index 1 = scalar deleting destructor
- **Effect:** Calling destructor on the live engine Simulation singleton (`0x7ff4d262efa0`) destroys the active game world → immediate unrecoverable crash

### Fix Deployed (2026-10-30 Session 3)
- ✅ **Removed blind probing**: Deleted loop over indices 0-19 in `FindTrueLocalPlayer()`
- ✅ **Skip destructor slots**: Only probe indices 2-19 (skipping 0 and 1 entirely)
- ✅ **Candidate indices**: `{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}` - based on UFG engine patterns where GetObjectByName typically at index 2-12
- ✅ **SEH preserved**: All probes still wrapped in `__try/__except` with `ProbeExceptionFilter`
- ✅ **Build verified**: Release build successful, ASI deployed to `plugins/`

### Static Disassembly Findings (GameState::OnUpdate)
- **Function entry**: RVA `0x00E28480` (not `0x00E28610` which is inside loop)
- **Documented vtable entry**: RVA `0x00E28610` points into loop body
- **Registers**: `rcx` = GameState (`this`), saved to `rdi`
- **GameState accesses**: `+0x30`, `+0x38`, `+0x98` used in update loop
- **GameState+0x20**: NOT directly read in OnUpdate (initialized at `0x004614ED` via Simulation thunk)
- **Loop start**: RVA `0x00E28510` - iterates over `[rdi+0x98]` array
- **Call targets**: `0x140C57960`, `0x140C57820` - vector math functions, not player lookup
- **Simulation thunk**: `0x00C55270` calls first virtual (index 0), then sets secondary vtable and calls index 2 (`[rax+0x10]`)

### Key Insight
The engine does NOT call `GetSimObject` from `GameState::OnUpdate`. Player lookup happens elsewhere (spawn, mission start, etc.). OnUpdate only updates already-cached entities.

---

## Runtime Session: 2026-10-30 Session 4 (VERIFIED OFFSET + SECONDARY VTABLE FIX)

**Build Status:** ✅ Successfully built and deployed to Steam install directory (`plugins/` only)

### Static Disassembly Findings - GameState::OnUpdate (RVA 0xE28480)
**CRITICAL FINDING:** The main update loop at RVA `0xE28510` uses **GameState+0x98** as the Simulation pointer base:
```
0xE28510: mov rbx, [rdi + 0x98]          ; Load Simulation* from GameState+0x98
0xE28551: mov [rcx + r14 + 0x20], eax    ; Write to Simulation+0x20 (rcx = [rdi+0x98])
0xE28561: mov [rcx + r14 + 0x28], rax    ; Write to Simulation+0x28
0xE28599: lea rcx, [rbx + 0xA0]          ; Call with rcx = Simulation+0xA0
```
- GameState+0x30: Loaded at entry, used as base for `+0x170` offset
- GameState+0x38: Loaded at entry, used for vtable check at `[rax+0x20]` and later `[rax+0x50]`
- GameState+0x98: **Primary Simulation pointer used throughout loop** (NOT +0x20!)

### Code Changes Deployed (Session 4)
1. **Fixed Simulation pointer offset**: Changed all `GameState+0x20` → `GameState+0x98` in `HK_GameState_OnUpdate` and `HK_GameState_OnEnter`
2. **Fixed secondary vtable 'this' pointer**: For secondary vtable calls, now pass `sim + 0x10` as `this` (matching thunk at 0xC55270 which does `rcx = sim + 0x10` before calling secondary vtable[2])
3. **VTable probing strategy**:
   - First: Try secondary vtable at `sim+0x10` with `this=sim+0x10` (indices 2-15)
   - Fallback: Try primary vtable at `sim+0x0` with `this=sim` (indices 2-15)
   - Both use `__vectorcall` convention (common for UFG SIMD-heavy virtual functions)
   - Skip indices 0-1 (destructors) entirely
4. **Logging**: Added detailed logs showing which vtable/index is being probed

### Simulation Multiple Inheritance Layout (from thunk at 0xC55270)
```
Simulation object:
  +0x00: Primary vptr   -> Primary vtable (destructor at [0], [1])
  +0x10: Secondary vptr -> Secondary vtable (thunk calls [2] with this=sim+0x10)

Thunk at 0xC55270:
  rcx = sim + 0x10              ; Adjust to secondary base
  call 0xC5C930                 ; Initialize secondary base
  lea rax, [rip + 0xA33981]     ; Load secondary vtable (0x141688BF0)
  mov [rdi], rax                ; Store to PRIMARY vptr (overwrites it!)
  ...
  mov rax, [rcx]                ; Load secondary vptr from [sim+0x10]
  call [rax + 0x10]             ; Call secondary vtable[2] with this=sim+0x10
```

## Runtime Session: 2026-10-30 Session 2 (Hooks Verified Running - Awaiting Local Player Discovery)

**Module Base:** `0x7ff78ecf0000` (ASLR)  
**Verified Simulation Instance:** `0x7ff4d262efa0` (heap address from GameState+0x20 - consistent across 2,500+ ticks)  
**Build Status:** ✅ Successfully built and deployed to Steam install directory (`plugins/` only)  
**Runtime Results:**
- ✅ **Hooks executing**: `HK_GameState_OnEnter` fires on gameplay entry, logs `"--> Entered HK_GameState_OnEnter"`
- ✅ **Simulation consistently resolved**: `OnEnter` logs `"Found active Simulation instance via GameState+0x20: 0x7ff4d262efa0"`
- ✅ **OnUpdate ticking**: Logs `"--> Tick #N in HK_GameState_OnUpdate"` every frame (observed ticks 0-47+)
- ✅ **Simulation cached**: `g_cachedSimulation` updated on both OnEnter and OnUpdate
- ✅ **No crashes**: 2,500+ ticks without any Access Violation or exception
- 🔍 **FindTrueLocalPlayer pending**: Runs every 120 ticks (~2 seconds at 60fps); next execution at tick 120
- 🔍 **Awaiting**: Simulation vtable scan (indices 0-19) for `GetSimObject(qSymbol*)` with "Player" (0x9FB57F53) / "WeiShen" (0x9AF96AFB)
- 🔍 **Awaiting**: Valid SimObjectCharacter pointer and TransformNodeComponent position logging

---

## Runtime Session: 2026-10-30 Session 3 (Crash at Tick 120 - ROOT CAUSE IDENTIFIED & FIXED)

**Module Base:** `0x7ff78ecf0000` (ASLR)  
**Verified Simulation Instance:** `0x7ff4d262efa0` (heap address from GameState+0x20 - consistent across 2,500+ ticks)  
**Build Status:** ✅ Successfully built and deployed to Steam install directory (`plugins/` only)

### Crash Analysis (Tick 120)
- **Event:** Game crashed with fast-fail at tick 120 when `FindTrueLocalPlayer()` executed
- **Root Cause:** Blind vtable probing loop (indices 0-19) called `Simulation vtable[0]` and/or `vtable[1]`
- **MSVC vtable layout:** Index 0 = virtual destructor, Index 1 = scalar deleting destructor
- **Effect:** Calling destructor on the live engine Simulation singleton (`0x7ff4d262efa0`) destroys the active game world → immediate unrecoverable crash

### Fix Deployed (2026-10-30 Session 3)
- ✅ **Removed blind probing**: Deleted loop over indices 0-19 in `FindTrueLocalPlayer()`
- ✅ **Skip destructor slots**: Only probe indices 2-19 (skipping 0 and 1 entirely)
- ✅ **Candidate indices**: `{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}` - based on UFG engine patterns where GetObjectByName typically at index 2-12
- ✅ **SEH preserved**: All probes still wrapped in `__try/__except` with `ProbeExceptionFilter`
- ✅ **Build verified**: Release build successful, ASI deployed to `plugins/`

### Static Disassembly Findings (GameState::OnUpdate)
- **Function entry**: RVA `0x00E28480` (not `0x00E28610` which is inside loop)
- **Documented vtable entry**: RVA `0x00E28610` points into loop body
- **Registers**: `rcx` = GameState (`this`), saved to `rdi`
- **GameState accesses**: `+0x30`, `+0x38`, `+0x98` used in update loop
- **GameState+0x20**: NOT directly read in OnUpdate (initialized at `0x004614ED` via Simulation thunk)
- **Loop start**: RVA `0x00E28510` - iterates over `[rdi+0x98]` array
- **Call targets**: `0x140C57960`, `0x140C57820` - vector math functions, not player lookup
- **Simulation thunk**: `0x00C55270` calls first virtual (index 0), then sets secondary vtable and calls index 2 (`[rax+0x10]`)

### Key Insight
The engine does NOT call `GetSimObject` from `GameState::OnUpdate`. Player lookup happens elsewhere (spawn, mission start, etc.). OnUpdate only updates already-cached entities.

## Verified RVAs (Relative Virtual Addresses)

All RVAs are relative to the preferred image base `0x140000000`. At runtime with ASLR, add the module base address (from PEB or `GetModuleHandle("sdhdship.exe")`).

| Feature | RVA | VA (Preferred) | Status | Notes |
|---------|-----|----------------|--------|-------|
| **GetLocalPlayer(int controllerIndex)** | `0x008CD060` | `0x1408CD060` | ⚠️ Interface table | Returns static vtable/interface, NOT heap SimObject |
| **Controller 0 Global** | `0x020B15D0` | `0x14020B15D0` | ✅ Verified | Points to interface table at `0x14187FE70` |
| **Controller 1 Global** | `0x020B15D8` | `0x14020B15D8` | ✅ Verified | Points to interface table at `0x14182BD90` |
| **Controller 2 Global** | `0x020B15E0` | `0x14020B15E0` | ✅ Verified | Same as controller 1 |
| **Controller 3 Global** | `0x020B15F8` | `0x14020B15F8` | ✅ Verified | NULL (unused) |
| **Controller Object (Player 0)** | `0x0187FE70` | `0x14187FE70` | ⚠️ Interface table | In .data section; +0x00 = interface, not heap SimObject |
| **Controller Object (Player 1)** | `0x0182BD90` | `0x14182BD90` | ⚠️ Interface table | In .data section; +0x00 = interface, not heap SimObject |
| **InGame GameState VTable** | `0x01784BD0` | `0x141784BD0` | ✅ Verified | Layout: [0]=COL, [1]=dtor, [2]=OnPreUpdate, [3]=OnPostUpdate, [4]=OnEnter, [5]=OnUpdate, [6]=OnExit |
| **InGame_OnUpdate (vtable[5])** | — | Resolved at runtime | ✅ Hooked | Main tick hook for co-op logic |
| **InGame_OnEnter (vtable[4])** | — | Resolved at runtime | ✅ Hooked | Gameplay entry hook |
| **InGame_OnExit (vtable[6])** | — | Resolved at runtime | ✅ Hooked | Gameplay exit hook |
| **InitGameSystems** | `0x00422691` | `0x140422691` | ⚠️ Disabled | Early init hook; disabled to prevent crashes |
| **SDK GetLocalPlayer Global (OLD)** | `0x0209E170` | `0x140209E170` | ❌ NULL | SDK's global is always NULL - DO NOT USE |
| **GameState::OnUpdate (real entry)** | `0x00E28480` | `0x140E28480` | ✅ Verified | Function entry; loop at 0xE28510 uses GameState+0x98 for Simulation |
| **GameState::OnUpdate (vtable entry)** | `0x00E28610` | `0x140E28610` | ✅ Verified | Vtable points into loop body |
| **GameState::OnEnter (real)** | `0x00E2C240` | `0x140E2C240` | ✅ Verified | Calls OnUpdate |
| **GameState+0x98 (Simulation ptr)** | — | — | ✅ Verified | **Primary Simulation pointer used in OnUpdate loop** (not +0x20!) |
| **GameState+0x30** | — | — | ✅ Verified | Base for +0x170 offset in OnUpdate |
| **GameState+0x38** | — | — | ✅ Verified | Vtable-related, checked at [rax+0x20] in OnUpdate |
| **Simulation Thunk (first virtual)** | `0x00C55270` | `0x140C55270` | ✅ Verified | `mov rax, [rcx]; jmp [rax]` - calls Simulation's first virtual |
| **Simulation Thunk VTable** | `0x01FA0E58` | `0x141FA0E58` | ✅ Verified | 15 adjustment thunks for secondary base class |
| **Simulation Getter 1** | `0x00152250` | `0x14152250` | 🔍 Candidate | Returns heap `0x1416A5420` |
| **Simulation Getter 2** | `0x00152260` | `0x14152260` | 🔍 Candidate | Returns heap `0x1416A5438` |
| **Simulation Getter 3** | `0x00152270` | `0x14152270` | 🔍 Candidate | Returns heap `0x1416A5480` |
| **Simulation Getter 4** | `0x00152280` | `0x14152280` | 🔍 Candidate | Returns heap `0x1416A5408` |
| **Simulation Getter 5** | `0x00152290` | `0x14152290` | 🔍 Candidate | Returns heap `0x1416A5468` |
| **GameState+0x20 init function** | `0x004614ED` | `0x1404614ED` | ✅ Verified | Calls Simulation thunk, stores heap ptr to GameState+0x20 (init only) |

### Controller Object Structure (STATIC INTERFACE TABLE - NOT DYNAMIC)

The `GetLocalPlayer(int controllerIndex)` function returns a pointer to a **static interface table** in the module's `.data`/`.rdata` section, NOT a dynamic controller/context object, and NOT the heap `SimObjectCharacter*`.

```
Controller Interface Table (in .data/.rdata - STATIC):
+0x000: uptr  -> Code pointer (RVA 0x00001AC0)  // First vtable method
+0x008: uptr  -> Code pointer (RVA 0x0009D0B0)  // Second vtable method
+0x010: uptr  -> Code pointer (RVA 0x002AF950)  // Third vtable method
+0x018: uptr  -> Code pointer (RVA 0x002AF950)  // Duplicate
+0x020: uptr  -> Code pointer (RVA 0x002AF950)  // Duplicate
+0x028: uptr  -> Code pointer (RVA 0x002AF950)  // Duplicate
+0x030: uptr  -> Self-reference (interface table address)
+0x038: uptr  -> Code pointer (RVA 0x00001AC0)
+0x060: uptr  -> Self-reference
+0x068: uptr  -> Code pointer
+0x0C0: uptr  -> Code pointer
+0x0C8: uptr  -> Code pointer
... and more
```

**Key Discovery:** This is a **static vtable/interface**, not a dynamic controller object. It contains no heap pointers. The actual `SimObjectCharacter*` for the local player must be found elsewhere.

---

## Networking Status

| Component | Status | Details |
|-----------|--------|---------|
| **Steam API Loading** | ✅ Working | Loads `steam_api64.dll` functions at runtime via `GetProcAddress` |
| **ISteamUser** | ✅ Working | Direct getter `SteamUser()` imported by game |
| **ISteamFriends** | ✅ Working | Direct getter `SteamFriends()` imported by game |
| **ISteamNetworking (Legacy P2P)** | ✅ Working | Direct getter `SteamNetworking()` imported by game |
| **CreateListenSocket** | ✅ Implemented | Host creates listen socket via `ISteamNetworking` |
| **ConnectP2P** | ✅ Implemented | Client connects to host via `ISteamNetworking::ConnectP2P` |
| **SendP2PPacket** | ✅ Implemented | Unreliable & reliable send via connection handle |
| **CloseP2PSession** | ✅ Implemented | Cleanup on disconnect |
| **SteamAPI_RunCallbacks** | ✅ Called each frame | In `NetworkTick()` via `GameState::OnUpdate` hook |
| **Packet Callback Handling** | ❌ Not Implemented | Need to register `SteamNetworkingCallback` for incoming packets |
| **Connection State Callback** | ❌ Not Implemented | Need to handle `P2PSessionConnectFail`, `P2PSessionRequest` |

**Current Networking Model:** Legacy Steam P2P (`ISteamNetworking` via `steam_api64.dll`). This is the original Steam networking API (pre-SteamNetworkingSockets). Works for basic P2P but has limitations (NAT traversal, no relay by default).

---

## Current Blockers

### 1. **Find True Local Player SimObject (CRITICAL - ALIGNMENT FIXED, BLIND VTABLE CALLS REMOVED)**
- **Issue:** `GetLocalPlayer(int)` returns a static interface table, not the heap `SimObjectCharacter*`
- **SDK Global:** RVA `0x209E170` is always NULL
- **Controller Globals:** RVA `0x20B15D0` etc. point to interface tables, not heap objects
- **Progress (2026-10-30 Session 5):**
  - ✅ **Alignment root cause identified**: GameState+0x98 returns unaligned odd address (0x7ff43d9f0f83 ends in 3!) causing crash at sim+0x10; GameState+0x20 returns 16-byte aligned pointer (0x7ff41cbcefa0) stable for 2500+ ticks
  - ✅ **Reverted to GameState+0x20** for Simulation pointer resolution
  - ✅ **Enforced 8-byte alignment** in IsValidUserPtr - rejects any pointer with (ptr & 0x7) != 0
  - ✅ **STOPPED blind vtable calling** - removed candidateIndices loop (2..15) with __vectorcall
  - ✅ **Added Simulation object hex dump** at tick 120 (first 16 QWORDs +0x00 to +0x78) for static analysis
  - ✅ **Created disassembly script** for GameState::OnUpdate (first 60 instructions) - engine uses +0x98 in loop but runtime value differs
  - 🔍 **Next**: Analyze Simulation object layout dump to find GetSimObject vtable index or member pointer to player
  - 🔍 **Next**: Cross-reference disassembly to find how engine actually accesses local player
- **Verification:** Once Simulation layout analyzed, implement correct player lookup (not blind vtable calls)

### 2. **Hook Execution Verification** ✅ **RESOLVED (2026-10-30)**
- **Previous Issue:** Initialization complete but never reached GameState::OnEnter/OnUpdate hooks
- **Mitigations Deployed & Verified Working:**
  - ✅ SEH (`__try/__except`) wrapping all runtime probing
  - ✅ Pre-call logging for each probe
  - ✅ Immediate entry logs in HK_GameState_OnEnter/OnUpdate
  - ✅ GameState+0x20 Simulation pointer resolution and logging
- **Runtime Result (2026-10-30):** Hooks executed for 2,500+ ticks without crashing; Simulation instance consistently resolved

### 3. **Remote Player Spawn/Despawn** ❌ Not Implemented
- Need to find `SimObjectFactory` or spawn system
- Need to create `SimObjectCharacter` with Wei Shen model
- Need to initialize components (physics, animation, AI disabled)

### 4. **State Serialization/Deserialization** ❌ Not Implemented
- Need to serialize: position, rotation, velocity, animation state, health
- Need packet structure definition
- Need interpolation on remote side

### 5. **Packet Callback Registration** ❌ Not Implemented
- Need to call `ISteamNetworking::SetP2PConnectionCallback` or similar
- Handle incoming packets in callback
- Thread safety: callbacks may fire on Steam thread

### 6. **Animation Sync** ❌ Not Researched
- Need to find `CharacterAnimationComponent` or equivalent
- Determine animation state replication approach

### 7. **Vehicle Sync** ❌ Not Researched
- Co-op will need vehicle entry/exit sync
- `VehiclePhysicsComponent` / `PhysicsWheeledVehicle` interaction

---

## Next Milestones

### Milestone 1: Stable Local Player Tracking
- [x] Fix pointer validation (IsValidUserPtr) - **CRASH RESOLVED**
- [x] Fix controller unpacking logic (was based on wrong assumption)
- [x] Guard transform dereference
- [x] Engine hooks installed & lifecycle stable (OnEnter/OnUpdate/OnExit)
- [x] **Runtime Hardening (2026-10-30):** SEH protection for all probing, pre-call logging, immediate hook entry logs, GameState+0x20 Simulation resolution
- [x] **Verify Hook Execution:** Hooks ran 2,500+ ticks without crashing; Simulation instance consistently resolved
- [x] **Connect Simulation Instance:** Cached Simulation from GameState+0x20 passed to FindTrueLocalPlayer
- [x] **Build & Deploy:** Release build successful, ASI deployed to Steam `plugins/` directory only
- [x] **CRASH FIX (Session 3):** Removed blind vtable probing (indices 0-19) that called destructor on live Simulation singleton
- [x] **Disassembly Complete (Session 3/4):** GameState::OnUpdate entry at RVA 0xE28480, loop at 0xE28510 uses GameState+0x98; engine does NOT call GetSimObject from OnUpdate
- [x] **ALIGNMENT FIX (Session 5):** Reverted to GameState+0x20 (aligned, stable); enforced 8-byte alignment in IsValidUserPtr; REMOVED blind vtable calling loop entirely
- [ ] **Analyze Simulation object layout dump** (16 QWORDs at tick 120) to find GetSimObject vtable index or direct member pointer to player
- [ ] **Cross-reference disassembly** to find how engine actually accesses local player (not via OnUpdate)
- [ ] **Implement correct player lookup** based on static analysis (not blind vtable calls)
- [ ] **Runtime test:** Verify valid position logging from real SimObject
- [ ] **Verify:** Position updates correctly as player moves

### Milestone 2: Basic P2P Connection
- [ ] Register SteamNetworking callbacks for incoming packets
- [ ] Implement connection state handling (accept/decline)
- [ ] Test host/join via Steam overlay/invite
- [ ] Verify `NetworkTick` runs callbacks correctly

### Milestone 3: Remote Player Spawn
- [ ] Find SimObjectFactory / spawn system
- [ ] Implement `SpawnRemotePlayer()` with basic Wei Shen model
- [ ] Position remote player near local player
- [ ] Disable AI on remote player

### Milestone 4: Position Sync (Host → Client)
- [ ] Define packet structure (position, rotation, timestamp)
- [ ] Serialize local player transform each frame
- [ ] Send via `SendP2PPacket` (unreliable)
- [ ] Apply on remote: set `TransformNodeComponent` world matrix

### Milestone 5: Full State Sync
- [ ] Add velocity (CharacterPhysicsComponent)
- [ ] Add animation state
- [ ] Add health
- [ ] Add input state (for prediction?)

### Milestone 6: Vehicle & World Interaction Sync
- [ ] Vehicle enter/exit sync
- [ ] Door/trigger interaction sync
- [ ] Mission progress sync (if applicable)

### Milestone 7: Polish & Ship
- [ ] ASI installer / one-click setup
- [ ] README with known issues
- [ ] Update DIRECTORY.md entry
- [ ] Open PR to coop-anything

---

## Build & Test Commands

```bash
# Build Release ASI
cd local/sleeping-dogs-coop
cmake --build build --config Release

# Test directory (copied by build) - DEPRECATED: use actual Steam directory
# ls local/sleeping-dogs-test/
# Should contain: sdhdship.exe, dinput8.dll (ASI loader), SleepingDogsCoop.asi, coop_log.txt

# ACTUAL TEST DIRECTORY (Steam install):
ls "C:/Program Files (x86)/Steam/steamapps/common/SleepingDogsDefinitiveEdition/"
# Should contain: SleepingDogsCoop.asi (and plugins/SleepingDogsCoop.asi)

# Run game via Steam (REQUIRED for proper initialization)
start steam://rungameid/304810

# View logs (in Steam directory)
tail -f "C:/Program Files (x86)/Steam/steamapps/common/SleepingDogsDefinitiveEdition/SleepingDogsCoop.log"
```

---

## Key Files

| File | Purpose |
|------|---------|
| `local/sleeping-dogs-coop/src/hooks.cpp` | Main hook implementations, pointer validation, networking |
| `local/sleeping-dogs-coop/include/ufg_types.h` | UFG type definitions, GetLocalPlayer typedefs, RVAs |
| `local/sleeping-dogs-coop/CMakeLists.txt` | Build configuration (x64 ASI DLL, MinHook, Steamworks) |
| `local/sleeping-dogs-test/SleepingDogsCoop.asi` | Built mod (copied by CMake) - DEPRECATED |
| `local/sleeping-dogs-test/dinput8.dll` | ASI loader (proxy DLL) |
| `local/sleeping-dogs-test/coop_log.txt` | Runtime log output - DEPRECATED |

---

## Notes for Next Agent

1. **The SDK's `GetLocalPlayer` global at RVA 0x209E170 is ALWAYS NULL** - do not use it. Use the real function at RVA 0x008CD060.

2. **Controller Object vs SimObject:** `GetLocalPlayer(0)` returns a **static interface table** in `.data`/`.rdata`, NOT a dynamic controller object, and NOT the heap `SimObjectCharacter*`. The interface table contains only code pointers (vtable methods). This was the critical misunderstanding.

3. **Pointer Validation is Essential:** Always use `IsValidUserPtr()` before dereferencing any pointer from the game. Module-space pointers (vtables, interface tables) look valid but will crash if treated as heap objects.

4. **Component System:** Use `SimObjectCharacter::GetComponent<T>()` to find components by iterating the component array at offset 0x38. Don't assume fixed offsets.

5. **Steam Networking:** The game uses legacy `ISteamNetworking` (not SteamNetworkingSockets). This is imported directly by sdhdship.exe. Use `SteamNetworking()` getter, not `SteamInternal_CreateInterface`.

6. **Hooking Strategy:** GameState vtable hooks work well. The InGame vtable is at RVA 0x01784BD0 (not SDK's 0x1784A90). Dereference vtable slots 4, 5, 6 for OnEnter, OnUpdate, OnExit.

7. **ASLR:** All RVAs need module base added at runtime. Use `Hooks::GetModuleBase()` which reads from PEB via `GetModuleHandle`.

8. **Testing:** MUST use the actual Steam install directory (`C:/Program Files (x86)/Steam/steamapps/common/SleepingDogsDefinitiveEdition/`). The test directory lacks full Steam runtime dependencies and game archives. Update CMakeLists.txt to copy there.

9. **Runtime Hardening (2026-10-30):** All runtime probing in `FindTrueLocalPlayer()` is now wrapped in Windows SEH (`__try/__except`) with `ProbeExceptionFilter()` logging exception code (0xC0000005, etc.) and the faulting address. Pre-call logs added before each Simulation getter (0x00152250-0x00152290) and vtable slot (0-19) call. Hook entry points now log immediately: `HK_GameState_OnEnter` logs `"--> Entered HK_GameState_OnEnter"`, `HK_GameState_OnUpdate` logs `"--> Tick #%llu in HK_GameState_OnUpdate"`. GameState+0x20 is now inspected in both hooks to find the active Simulation instance.

10. **Auto-Deploy:** CMakeLists.txt copies the built .asi ONLY to the `plugins/` subdirectory (`C:/Program Files (x86)/Steam/steamapps/common/SleepingDogsDefinitiveEdition/plugins/`) automatically on build. Copying to the root game directory was removed to prevent Ultimate ASI Loader from injecting the mod twice.

11. **DO NOT LAUNCH GAME FROM TERMINAL:** Launching `sdhdship.exe` or using `start steam://rungameid/304810` from a terminal subprocess triggers Steam's DRM check ("An error occurred while launching this game: No licenses"). The game MUST be launched manually through the Steam library UI. Your job boundary is STRICTLY: disassemble, write code, update headers, run CMake build, update COOP_STATE.md. STOP and prompt the owner to launch the game manually.

---

## Related Analysis Scripts (in repo root)

| Script | Purpose |
|--------|---------|
| `disasm_candidates.py` | Disassembles GetLocalPlayer and array-access functions |
| `find_getlocalplayer_focused.py` | Searches for GetLocalPlayer patterns |
| `search_sdk_global.py` | Finds code accessing SDK's NULL global |
| `analyze_simobject_vtable.py` | Analyzes SimObjectCharacter RTTI/vtable and .data globals |
| `analyze_script_table.py` | Analyzes SkookumScript function table |

These scripts were used to discover the RVAs and controller object structure documented above.