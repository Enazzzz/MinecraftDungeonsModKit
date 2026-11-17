# Minecraft Dungeons Mod Kit

Offline-only **native mod runtime** for the Steam release of Minecraft Dungeons (Unreal Engine 4.22.3).

The first milestone injects a runtime into `Dungeons-Win64-Shipping.exe`, fingerprints the supported build, inspects UE objects, exposes a local control pipe, and loads native plugins — without patching the shipping executable or packaged assets.

## Components

| Piece | Role |
|-------|------|
| `mcd-launcher` | Inspect install, start/find the game, inject the runtime, talk over the named pipe |
| `mcd-runtime` | Fingerprint → build profile → signature scan → pipe + plugin host |
| Plugins | Native modules loaded by the runtime after it is ready |

## Requirements

- Windows
- CMake 3.24+
- Visual Studio 2022 (C++ desktop workload)
- A matching Steam Minecraft Dungeons install (see `docs/` for the supported build hash)

## Build

```powershell
cmake -S . -B build
cmake --build build --config Release
```

## Docs

Design and plans live under `docs/superpowers/`.

## Status

Active WIP. Unknown game builds are rejected until a matching profile exists.
