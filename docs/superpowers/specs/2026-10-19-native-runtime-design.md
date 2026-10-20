# Minecraft Dungeons Native Runtime Design

## Goal

Build an offline-only native mod runtime for the current Steam release of Minecraft Dungeons. The first milestone must inject safely into `Dungeons-Win64-Shipping.exe`, identify the supported game build, inspect Unreal Engine 4.22.3 objects, expose a local control interface, and load native plugins without modifying the original executable or packaged assets.

## Supported Build

The initial supported executable is:

- Path: `Dungeons\Binaries\Win64\Dungeons-Win64-Shipping.exe`
- SHA-256: `6A48471423B41CDCDD4F0322560DCAFAE0F433F3BC30721FAE861564A4F5CC73`
- Size: `37,814,288` bytes
- Engine family: Unreal Engine 4.22.3

The runtime must reject unknown executable hashes unless a matching build profile exists. Build profiles may use byte signatures rather than absolute virtual addresses, but each resolved address must pass structural validation before use.

## Components

### Launcher

`mcd-launcher.exe` provides commands to:

- Inspect the installed game and report its fingerprint.
- Find or start the Steam game process.
- Inject the runtime DLL using the Windows `LoadLibraryW` mechanism.
- Connect to the runtime's local named pipe.
- Request status, object dumps, plugin operations, and a clean runtime shutdown.
- Install, inspect, and remove a narrowly scoped Windows Firewall outbound rule for the shipping executable.

The launcher must report actionable errors and must not silently retry injection.

### Runtime

`mcd-runtime.dll` performs only minimal bookkeeping in `DllMain`. Before scheduling detached work, process attach irreversibly pins the already loaded image with the Kernel32 `GetModuleHandleExW` process-lifetime pin. The pin prevents any injector or client `FreeLibrary` call from unmapping code or data while the worker can execute. A dedicated initialization thread owns all scanning and setup so loader-lock-sensitive work does not occur in `DllMain`; the pin operation itself neither loads another DLL nor invokes user code.

Runtime shutdown is behavioral rather than an image unload: it stops accepting commands, cancels and resolves pending I/O, closes server and event handles, blocks new callbacks, drains active work, and lets every runtime-owned thread exit. The resulting image is inert but remains mapped until host-process exit. No runtime API exposes an unload path.

Initialization proceeds in this order:

1. Open the diagnostic log.
2. Fingerprint the host executable.
3. Select an exact build profile.
4. Scan executable sections for required Unreal symbols.
5. Validate every resolved symbol and object layout.
6. Start the local control pipe.
7. Initialize the game-thread dispatcher.
8. Enable object inspection and optional console support.
9. Start the plugin host.
10. Report the runtime as ready.

Any failure before readiness unwinds initialized components in reverse order.

### Signature Scanner and Build Profiles

The scanner reads committed PE sections from the already loaded host module. A signature contains a byte pattern, wildcard mask, target section, resolution rule, and validation callback.

Profiles identify symbols needed by a feature. The baseline profile targets:

- Global UObject array.
- Global name storage or the corresponding UE 4.22 name conversion functions.
- `UObject::ProcessEvent`.
- A reliable game-thread execution point.
- Console construction paths when they can be validated.

Optional symbols cannot prevent the diagnostic runtime from loading. Required symbols must be resolved before object access is enabled.

### Unreal Engine Bridge

The engine bridge contains the minimum mirrored UE 4.22.3 types needed for validated read-only inspection. It does not depend on a generated full SDK.

Initial capabilities are:

- Iterate valid `UObject` entries.
- Resolve object names and full paths.
- Find objects by class and path.
- Describe reflected classes, functions, and properties.
- Dump object metadata to deterministic text and JSON outputs.
- Observe selected `ProcessEvent` calls through filtered hooks.
- Schedule engine access on the game thread.

Writes and function invocation remain disabled until the relevant object layouts and calling conventions have dedicated tests.

### Hook Manager

The hook manager wraps the selected detour library and owns hook lifetime. Hooks are installed transactionally: target validation occurs first, then hooks are enabled together. Shutdown disables hooks before unloading plugins or releasing engine state.

Hook callbacks must avoid allocations, blocking I/O, and plugin loading while executing on game threads. Events destined for diagnostics are copied into bounded queues and processed by a worker.

### Plugin Host

Plugins are named `*-mod.dll` and live outside the game directory by default. They export a versioned C ABI entry point and receive a table of runtime services.

The first API version exposes:

- Structured logging.
- Build and runtime metadata.
- Read-only object lookup and enumeration.
- Game-thread task scheduling.
- Registration of filtered Unreal event observers.
- Explicit plugin shutdown callbacks.

The host validates API versions before invoking plugin code. A plugin failure disables that plugin without invalidating runtime state where Windows exception boundaries allow recovery. Hot loading is supported in the first milestone; unloading is allowed only when no plugin callbacks or game-thread tasks remain active.

### Local Control Channel

The launcher and runtime communicate through a named pipe restricted to the current Windows user. Messages use a length-prefixed, versioned format with bounded payload sizes.

The first commands are:

- `status`
- `dump-objects`
- `find-object`
- `list-plugins`
- `load-plugin`
- `unload-plugin`
- `shutdown`

Malformed or unsupported requests receive explicit errors and cannot invoke arbitrary shell commands.

Pipe shutdown uses `CancelIoEx` and a bounded completion wait. `ERROR_NOT_FOUND` is treated only as a completion race and the runtime still resolves the `OVERLAPPED` result. Other cancellation failures retain their originating Win32 error. If the kernel does not resolve an operation before the bound, the runtime closes the pipe handle and quarantines the heap-owned `OVERLAPPED` structure and transfer buffer for process lifetime; this avoids dangling kernel references without leaving a callback, worker, or auxiliary handle active.

### Offline Enforcement

The launcher can create a named Windows Firewall outbound block rule scoped only to the full path of `Dungeons-Win64-Shipping.exe`. Rule installation requires elevation and is separate from normal injection. The launcher can display and remove the exact rule it owns.

The runtime also maintains an offline guard. Gameplay-modifying plugin services remain unavailable when the engine reports a networked world or non-standalone net mode. Diagnostic read-only services can remain active.

## Data and Control Flow

The user starts the game normally or through the launcher. The launcher validates the on-disk executable, locates the corresponding process, verifies the process image path, and injects the runtime. The runtime validates the in-memory module and resolves its engine bridge. Once ready, the launcher connects over the named pipe and issues diagnostic or plugin commands.

Unreal access occurs on the game thread unless a service is explicitly documented as thread-safe. Hook callbacks enqueue lightweight event records. Worker threads handle logging, serialization, pipe I/O, and plugin file discovery.

## Failure Handling

- Unsupported build: do not scan with another profile; log the fingerprint and stop.
- Ambiguous signature: reject the symbol and list all candidate offsets.
- Failed symbol validation: disable the dependent feature; required-symbol failure prevents readiness.
- Injection failure: leave the game process running and report the Windows error.
- Pipe failure: keep the runtime operational and permit a later reconnect.
- Plugin initialization failure: quarantine that plugin for the session and continue.
- Hook failure: roll back every hook installed in the same transaction.
- Runtime shutdown: stop accepting commands, resolve pending I/O, block new callbacks, drain tasks, unload plugins, remove hooks, close logs and handles, and end every runtime-owned thread; keep the inert process-pinned image mapped until host exit.

## Verification

Automated tests cover pattern parsing and scanning, PE section bounds, profile selection, protocol framing, plugin ABI negotiation, lifecycle ordering, and firewall command generation.

Integration verification for the supported Steam build must demonstrate:

1. The unmodified game reaches the main menu.
2. The launcher identifies the expected executable hash.
3. Injection produces a runtime-ready status without crashing the game.
4. Object dumping produces non-empty, structurally valid output.
5. A sample plugin loads, logs, observes a safe engine event, and shuts down.
6. Unknown-build simulation fails closed.
7. Repeated runtime startup does not inject twice.
8. The firewall rule blocks only the game executable and can be removed cleanly.

## Project Constraints

- Windows x64 and the current Steam build are the initial target.
- The implementation uses C++ with CMake and the installed Visual Studio 2022 toolchain.
- Source code uses tabs for indentation.
- Every function, method, and class has a concise documentation comment.
- The runtime does not bypass anti-cheat, DRM, authentication, or platform protections.
- Online and multiplayer gameplay modification is outside scope.
- Original game executables and packaged assets remain untouched.
