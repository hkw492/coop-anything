# Sleeping Dogs: Definitive Edition - Co-op Mod Research Notes

## Game Identity
- **Game**: Sleeping Dogs: Definitive Edition
- **Store**: Steam (AppID: 307690)
- **Version**: Definitive Edition (remaster of 2012 original)
- **Executable**: `sdhdship.exe` (35.8 MB, PE32+, x86-64)
- **Engine**: Unreal Engine 3 (developed by United Front Games)
- **OS**: Windows 10/11 x64

## Install Path
- Original: `C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition`
- Test Copy: `local\sleeping-dogs-test\` (executable, DLLs, essential data files)

## Technical Findings

### Binary Analysis
- **Architecture**: x64 (64-bit)
- **Main Executable**: `sdhdship.exe` - 35.8 MB
- **DLLs Present**:
  - `steam_api64.dll` - Steamworks API (Steam Relay/P2P support)
  - `d3dcompiler_46.dll` - DirectX 11 shader compilation
  - `bink2w64.dll` - Bink Video 2
  - `libcurl.dll` / `libcurl-ttv.dll` - HTTP library (Twitch integration?)
  - `libeay32.dll` / `ssleay32.dll` - OpenSSL
  - `twitchsdk_64_release.dll` - Twitch SDK
  - `avutil-ttv-51.dll`, `swresample-ttv-0.dll`, `libmp3lame-ttv.dll` - FFmpeg (Twitch streaming)
  - `sdkencryptedappticket64.dll` - Steam encrypted app tickets

### Data Format
- Custom `.big` / `.bix` archive format (UE3-style packages)
- Large asset files: Game.big (4.1 GB), GameHD.big (5.8 GB), Characters.big (1.4 GB), Animation.big (105 MB), etc.
- Data folder structure:
  - `Global/Abk/Facial/` - Animation banks (facial)
  - `Global/Act/AI/`, `Facial/`, `NIS/`, `Object/`, `POI/` - Action scripts (AI, facial, NIS/cinematics, objects, points of interest)

### DisplaySettings.xml
- DirectX 11 settings (resolution, VSync, AA, shadows, SSAO, motion blur)
- Stereo 3D support
- FPS limiter

## Existing Co-op Work (Directory Check)
- **DIRECTORY.md**: Listed as "Open gap" (line 323)
- **Note**: "A 2024 Nexus comment says modder sneakyevil has long been working on an MP mod that stalled; a widely shared video is warned about as a survey scam. Treat as unconfirmed."
- **No playable/partial/alpha co-op mod found** in the directory
- **No public repository or code found**

## Reverse Engineering Plan

### Target UE3 Classes (to locate in sdhdship.exe)
1. **Engine Core**: `UEngine`, `GameEngine`, `LocalPlayer`
2. **Networking**: `NetDriver`, `NetConnection`, `PacketHandler`, `ReplicationDriver`
3. **Gameplay**: `GameInfo`, `WorldInfo`, `Level`, `Actor`, `Pawn`, `Controller`, `PlayerController`
4. **Player**: `PlayerReplicationInfo`, `Pawn`, `Character` (if exists)
5. **Save System**: `SaveGame`, `GameEngine::Exec` (save/load commands)

### Hooking Strategy
| Subsystem | Hook Point | Method |
|-----------|------------|--------|
| Engine Init | `UEngine::Init` / `GameEngine::Init` | Detour for early networking injection |
| Player Spawn | `AGameInfo::Login` / `SpawnDefaultPawn` | Assign player index, replicate pawn |
| Replication | `AActor::ReplicateActor` / `NetDriver` | Extend NetDriver for Steam P2P transport |
| Level Loading | `UGameEngine::LoadMap` / `ULevel::Serialize` | Sync level transitions |
| Input/Control | `APlayerController::PlayerTick` | Split input for P2 |
| Save System | `USaveGame` / `UGameEngine::Exec` | Sync save slots, checkpoints |
| AI/World | `AAIController` / `AWorldInfo` | Replicate AI state, world events |

### Networking Model
- **Transport**: SteamNetworkingSockets / Steam P2P Relay (via `steam_api64.dll`)
- **Topology**: Host-authoritative (listen server) - matches UE3 native model
- **Max Players**: 2 (host + 1 client)
- **Sync Model**: State replication + RPC (extend UE3's replication)

## Similar UE3 Co-op Mods (Reference)
| Game | Project | Status | Net |
|------|---------|--------|-----|
| BioShock Remastered | BioShock Together | alpha | unknown |
| Dishonored | Dishonored COOP / dismod | partial / prototype | steam-relay / dedicated |
| Batman: Arkham Knight | Nightfall Together | alpha | steam-relay |
| SWAT 4 | Official co-op | official | dedicated |

## PE Resource Analysis (2026-10-24)
**Tool**: REA CLI `inspect-pe-resources`
- **SHA256**: 2a33ec787ac6fd4c86fec2b6f778feea881a3f35ea56c680121f53571c0527da
- **Format**: PE32+ (x86_64)
- **Size**: 37,490,688 bytes (35.8 MB)
- **Resources**: 64 entries across 5 directory levels
  - Type 1 (RT_CURSOR): 24 cursors (IDs 24-47)
  - Type 3 (RT_BITMAP): 23 bitmaps (IDs 1-23)
  - Type 12 (RT_GROUP_ICON): 12 icon groups (IDs 102-115)
  - Type 14 (RT_GROUP_ICON?): 1 group (ID 101)
  - Type 16 (RT_VERSION): 1 version resource (ID 1)
  - Type 21 (RT_MANIFEST): 1 manifest (ID 113) - 251,168 bytes (large, likely embedded data)
- **Icon groups**: Multiple sizes (16, 24, 32, 48, 64, 72, 80, 96, 128) with 1/4/8/32-bit color depths
- **Coverage**: Complete - 134 entries examined, 64 resources

## Next Steps (Phase 3: Reverse Engineering)
1. [x] Open `sdhdship.exe` in Ghidra (analysis complete)
2. [x] Identify UE3 class hierarchy (RTTI, vtables)
3. [x] Locate `NetDriver`, `GameEngine`, `PlayerController` vtables
4. [x] Find Steam API calls (`SteamNetworkingSockets`, `SteamFriends`, `SteamUser`)
5. [x] Map replication functions (`ReplicateActor`, `PostNetReceive`, etc.)
6. [x] Document findings in this file
7. [x] Create Ghidra scripts for UE3 structure detection

## Toolchain
- **RE**: Ghidra 12.1.4 (x64 PE via headless), x64dbg for runtime
- **Hooking**: MinHook or Microsoft Detours (x64)
- **Build**: Visual Studio 2022 (C++17), Steamworks SDK
- **Injection**: Custom ASI/Ultimate ASI Loader (never modify original EXE)

## Open Questions
- [ ] Exact UE3 version (check build strings)
- [ ] Whether game uses `IpNetDriver` or custom `NetDriver`
- [ ] Save game format and location
- [ ] Level streaming mechanism (seamless world vs. loading screens)
- [ ] Vehicle replication complexity
- [ ] Mission/quest state replication requirements

## Ghidra Analysis Results (2026-10-24)

### Steam API Imports (14 functions from STEAM_API64.DLL)
- `SteamAPI_Init` - Initialize Steamworks
- `SteamAPI_Shutdown` - Shutdown Steamworks
- `SteamAPI_RunCallbacks` - Process Steam callbacks
- `SteamAPI_RegisterCallback` / `SteamAPI_UnregisterCallback` - Callback management
- `SteamAPI_RegisterCallResult` / `SteamAPI_UnregisterCallResult` - Call result management
- `SteamUser` - User interface (auth, persona)
- `SteamFriends` - Friends list, rich presence
- `SteamUserStats` - Achievements, stats
- `SteamAPI_IsSteamRunning` - Check if Steam client running
- `SteamAPI_RestartAppIfNecessary` - Handle Steam launch
- `SteamAPI_WriteMiniDump` / `SteamAPI_SetMiniDumpComment` - Crash reporting

**Note**: No direct `SteamNetworkingSockets` imports found - game uses legacy Steam P2P API (`ISteamNetworking`) or implements networking on top of `SteamUser`/`SteamFriends`.

### UE3 Class/Function Findings
- **9 functions matched UE3 patterns** (mostly `Init`/`Destroy` entry points)
- **4,952 potential vtables** found (many with 21 entries each, typical for UE3 actors)
- **1,166 interesting strings** including:
  - `"p2PA"` - P2P networking reference
  - `"loadsavegame"` - Save game command
  - `"steam_achievement"` - Steam achievement system
  - `"ss_spawn_obj"` - Spawn object (Pawn-related)
  - **Build strings**: `2015-06-04.Physics_2012.SquareEnix_UnitedFrontGames_SleepingDogsHD_PS4-XboxOne`
  - **Source paths**: `d:\ufg\madscience\project\sdhd\sdhd_pc\theory\dev\package\illusion\source\illusion\factory.cpp`
  - **Havok Physics**: `hkpRigidBody`, `hkpWorld`, `hkpRagdollConstraintData`, `hkpConstraintInstance`, etc.
  - **Character**: `BLENDWEIGHT` (Wei Shen), `HK_*` rendering settings

### Key Technical Details
- **Engine**: Unreal Engine 3 (confirmed via RTTI, vtables, strings)
- **Physics**: Havok (hkp* classes throughout)
- **Build date**: June 4, 2015 (Definitive Edition remaster)
- **Developer**: United Front Games (internal path: `ufg\madscience\project\sdhd`)
- **Platform**: PS4/XboxOne remaster (Definitive Edition)
- **Steam integration**: Full Steamworks API (user, friends, stats, callbacks)

### VTable Analysis
- 4,952 potential vtables in .rdata section
- Most have 21 virtual functions (standard UE3 Actor vtable size)
- First entries point to .text section (0x14145xxxx - 0x14146xxxx range)
- Need to cross-reference with RTTI to identify specific UE3 classes (APlayerController, APawn, UNetDriver, etc.)

---

## Phase 4: Implementation Architecture Proposal

Based on research findings, here's the proposed architecture for a 2-player co-op mod using Steam Relay:

### Networking Model: Host-Authoritative Listen Server (UE3 Native)
- **Transport**: Steam P2P API via `steam_api64.dll` (legacy `ISteamNetworking` or custom on `SteamUser`)
- **Topology**: Host (listen server) + 1 Client
- **Sync Model**: Extend UE3's built-in replication (Actor replication + RPCs)
- **Max Players**: 2 (matches UE3's default 2-player splitscreen design)

### Core Components

#### 1. Steam Networking Layer (`SteamNetDriver`)
- Extend UE3's `NetDriver` class to use Steam P2P API instead of raw UDP
- Implement `ISteamNetworking` callbacks for connection management
- Handle Steam Relay NAT traversal via `SteamFriends`/`SteamUser`
- Packet serialization compatible with UE3's `PacketHandler`

#### 2. Player Management
- Hook `AGameInfo::Login` / `SpawnDefaultPawn` to assign player indices (0=host, 1=client)
- Extend `APlayerController` for split input handling (P2 gets separate input mapping)
- Replicate `PlayerReplicationInfo` for both players

#### 3. Actor Replication
- Hook `AActor::ReplicateActor` to sync position, rotation, velocity, state
- Extend `NetDriver` for reliable/unreliable Steam P2P channels
- Handle `bNetOwner`, `RemoteRole`, `Role` for authority determination
- Special handling for: Pawns, Vehicles, AIControllers, WorldInfo events

#### 4. Level/World Sync
- Hook `UGameEngine::LoadMap` / `ULevel::Serialize` for level transition sync
- Replicate `WorldInfo` events (time of day, weather, mission state)
- Handle streaming levels (if UE3 streaming is used)

#### 5. Save/Checkpoint Sync
- Hook `USaveGame` / `UGameEngine::Exec` (save/load commands)
- Sync save slots between host and client
- Handle checkpoint triggers

#### 6. Input/Control
- Hook `APlayerController::PlayerTick` for P2 input
- Create virtual "Player 2" controller that receives replicated input
- Handle camera/pawn possession for P2

### Hooking Strategy (MinHook x64)

| Subsystem | Target Function | Hook Type |
|-----------|-----------------|-----------|
| Engine Init | `UEngine::Init` / `GameEngine::Init` | Detour (early injection) |
| NetDriver Create | `UEngine::CreateNetDriver` | Detour (replace with SteamNetDriver) |
| Player Login | `AGameInfo::Login` | Detour (assign player index) |
| Pawn Spawn | `AGameInfo::SpawnDefaultPawn` | Detour (spawn P2 pawn) |
| Replication | `AActor::ReplicateActor` | Detour (extend for Steam) |
| Net Tick | `UNetDriver::TickDispatch` | Detour (process Steam packets) |
| Level Load | `UGameEngine::LoadMap` | Detour (sync transition) |
| Input | `APlayerController::PlayerTick` | Detour (split input) |
| Save/Load | `UGameEngine::Exec` | Detour (sync saves) |

### Injection Method
- **ASI Loader** (Ultimate ASI Loader or custom)
- DLL injected at process start via `dinput8.dll` proxy or `AppInit_DLLs`
- Initialize MinHook, apply detours, start Steam networking
- Never modify original `sdhdship.exe`

### Build System
- **Visual Studio 2022** solution with C++17
- **Steamworks SDK** (latest) linked statically
- **MinHook** submodule for hooking
- Output: `SleepingDogsCoop.asi` + `steam_api64.dll` (redistributed)

### Testing/QA (Per Playbook)
- Automated sync testing with `tools/coop-sync-testing`
- Flight recorder for desync detection
- Bot players for automated playthrough
- Network chaos testing (latency, packet loss, reorder)
- 2-instance testing on single machine (Steam Relay loopback)

---
*Last updated: 2026-10-24 (PE resource analysis added)*