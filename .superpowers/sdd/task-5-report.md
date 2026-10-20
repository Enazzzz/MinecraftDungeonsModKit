# Task 5 Report: Process Discovery, Injection, and Status CLI

## Result

Implemented the first launcher vertical slice:

- `inspect <game-exe>` canonicalizes and hashes the exact file, prints its byte size, uppercase SHA-256, and selected build profile.
- `inject <game-exe> <runtime-dll>` rejects unsupported builds and invalid DLL paths before process access, finds exactly one canonical process image match, avoids duplicate loads, and injects through remote `LoadLibraryW`.
- `status <pid>` performs a bounded request against the process-specific current-user runtime pipe, validates protocol framing, and prints the JSON payload.
- Stable exit codes distinguish usage (`2`), file validation (`3`), unsupported builds (`4`), discovery (`5`), injection (`6`), and status (`7`) failures.

## Security and Correctness Boundaries

- Process discovery uses `CreateToolhelp32Snapshot` and queries candidate paths with only `PROCESS_QUERY_LIMITED_INFORMATION`.
- Process selection is filename-prefiltered but accepted only after canonical full-path comparison. Zero or multiple canonical matches fail closed.
- Runtime DLL validation requires an absolute, existing regular file and returns its canonical path before any target-process handle is opened.
- Injection opens only:
  - `PROCESS_CREATE_THREAD`
  - `PROCESS_QUERY_LIMITED_INFORMATION`
  - `PROCESS_VM_OPERATION`
  - `PROCESS_VM_WRITE`
  - `PROCESS_VM_READ`
- Duplicate detection enumerates remote modules before opening the target with injection rights.
- `LoadLibraryW` is not called through a copied local pointer. The launcher validates the local export lies inside the local `kernel32` image, computes its RVA, checks arithmetic overflow, and applies that RVA to the remote `kernel32` base.
- Remote allocation and kernel handles use RAII. Completed and failed terminal thread paths explicitly release remote path memory and surface release failures.
- A 15-second loader-thread timeout is enforced. If completion cannot be proven, the small remote path allocation is deliberately retained because freeing memory that a still-running remote thread may read would create a cross-process use-after-free. Handles are still closed.
- Pipe operations use overlapped I/O with a shared five-second deadline. Timed-out operations are cancelled; operation storage is retained only if bounded cancellation completion cannot be proven.

## TDD Evidence

### RED 1: Initial launcher validation API

Added launcher tests for:

- relative runtime path rejection;
- missing absolute runtime rejection;
- canonicalization of an existing runtime;
- mismatched process-image rejection;
- case-insensitive Windows path comparison;
- remote export RVA derivation;
- invalid local export address rejection.

Command:

```powershell
cmake --build build --config Debug --target mcd_tests
```

Observed expected failure:

```text
launcher_tests.cpp(8,10): error C1083:
Cannot open include file: 'mcd/launcher/injector.hpp': No such file or directory
```

### GREEN 1

Implemented the launcher headers and core sources, then built and ran the focused test:

```powershell
cmake --build build --config Debug --target mcd_launcher_tests
.\build\tests\Debug\mcd_launcher_tests.exe
```

Observed: build exit `0`; focused test exit `0`.

### RED 2: Cross-process export upper bound

Added a regression proving an export at or beyond the local image extent is rejected.

Command:

```powershell
cmake --build build --config Debug --target mcd_launcher_tests
```

Observed expected compile failure because `remote_export_address` did not yet accept a module-size boundary.

### GREEN 2

Added PE image-size validation and bounded RVA derivation.

Command:

```powershell
cmake --build build --config Debug --target mcd_launcher_tests
.\build\tests\Debug\mcd_launcher_tests.exe
```

Observed: build exit `0`; focused test exit `0`.

## Automated Verification

Commands:

```powershell
cmake -S . -B build -A x64 -DBUILD_TESTING=ON
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
.\build\Debug\mcd-launcher.exe inspect "C:\Program Files (x86)\Steam\steamapps\common\MinecraftDungeons\Dungeons\Binaries\Win64\Dungeons-Win64-Shipping.exe"
```

Results:

- Configure: passed.
- Debug build: passed.
- CTest: `5/5` passed, `0` failed.
- Exact executable inspection:
  - size: `37814288`;
  - SHA-256: `6A48471423B41CDCDD4F0322560DCAFAE0F433F3BC30721FAE861564A4F5CC73`;
  - profile: `steam-2026-10-19`;
  - exit: `0`.

## Live Integration Evidence

The authorized Steam install was launched without modifying original game files. The offline hero-selection main menu was visibly ready before injection.

Final live run:

```text
runtime injected into process 28276
INJECT_EXIT=0
{"state":"ready","runtime_version":"0.1.0","profile_id":"steam-2026-10-19","process_id":28276}
STATUS_EXIT=0
runtime already loaded into process 28276
DUPLICATE_EXIT=0
Responding=True
```

The game remained visibly at the animated main menu and Windows reported it responding after injection and the duplicate-injection check. It was then closed normally with `Alt+F4`.

## Self-Review

- Verified unsupported fingerprint rejection precedes discovery.
- Verified runtime-path validation precedes discovery and target process access.
- The review hardening supersedes the initial duplicate-check ordering: one final-access process handle is now opened first and retained through duplicate inspection and injection.
- Hardened module matching so a same-named remote runtime whose path cannot be canonicalized fails closed instead of being ignored.
- Bounded the local export RVA by the mapped local PE image size and checked remote-address overflow.
- Preserved pending-operation storage on unresolved timeout/cancellation paths rather than introducing use-after-free.
- No Unreal hooks, firewall changes, executable modifications, or game-file changes were added.

## Concern

Windows provides no safe general-purpose way to cancel a remote thread blocked inside `LoadLibraryW`. On an unresolved 15-second timeout, freeing the remote path would violate the memory-lifetime boundary. The launcher therefore reports timeout, closes handles, and intentionally leaves only that path allocation in the target process. All confirmed terminal paths free it and report cleanup failures.

## Blocking Review Fixes

### Production hardening

- Injection now opens the selected PID once with the final least-required access mask before trusting process identity. It queries and canonicalizes the image path from that exact handle, revalidates it against the inspected executable, and holds the handle through architecture checks, synchronization, module inspection, allocation, write, and remote-thread completion.
- `IsWow64Process2` now identifies launcher and target effective machine types. Unknown or mismatched architecture fails with a specific error before module-RVA derivation.
- A bounded `Local\mcd-inject-<pid>-<build>` mutex serializes duplicate inspection and injection across launcher processes. The 15-second acquisition wait fails closed.
- Duplicate classification is monotonic: exact matches remain exact, while any same-basename different-path module makes the result ambiguous. Ambiguity has precedence and is reported explicitly.
- PID parsing now accepts only nonempty ASCII digits representing values `1..DWORD_MAX`; whitespace, signs, non-ASCII digits, suffixes, zero, and overflow are rejected.
- Existing least-required process rights, bounded loader waits, and remote-memory retention on uncertain completion remain unchanged.

### TDD evidence

Added focused tests before production changes for:

- strict PID parsing and `DWORD` overflow;
- native/WOW64 architecture compatibility decisions;
- exact, absent, and ambiguous module classifications plus monotonic merging;
- fragmented launcher-client status responses;
- bounded launcher-client response timeout;
- two target-lock contenders, proving the second cannot enter while the first owns the critical section.

RED command:

```powershell
cmake --build build --config Debug --target mcd_launcher_tests
```

Observed expected compilation failures for the not-yet-created `parse_process_id`, `architectures_compatible`, module classification, bounded client seam, and `TargetInjectionLock` interfaces.

GREEN focused verification:

```powershell
cmake --build build --config Debug --target mcd_protocol_tests mcd_runtime_tests mcd_launcher_tests
.\build\tests\Debug\mcd_protocol_tests.exe
.\build\tests\Debug\mcd_runtime_tests.exe
.\build\tests\Debug\mcd_launcher_tests.exe
```

Observed exit `0` for all three focused executables. Runtime output reported every named runtime test as `PASS`.

### Full Debug verification

```powershell
cmake -S . -B build -A x64 -DBUILD_TESTING=ON
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

Observed: configure and build exit `0`. The final post-review rerun reported CTest `5/5` passed, `0` failed in `0.60 sec`; the launcher suite, including synchronization and bounded pipe timeout, completed in `0.45 sec`. A CLI check also rejected `status +1` with usage exit `2`.

### Review-fix live evidence

Safe inspect:

```text
size: 37814288
sha256: 6A48471423B41CDCDD4F0322560DCAFAE0F433F3BC30721FAE861564A4F5CC73
profile: steam-2026-10-19
INSPECT_EXIT=0
```

The game was not running, so one fresh launch and injection were required. At the visibly ready offline hero-selection menu:

```text
runtime injected into process 30876
INJECT_EXIT=0
runtime already loaded into process 30876
DUPLICATE_EXIT=0
Responding=True
```

The status command issued immediately after injection observed the expected startup race (`pipe is unavailable`, exit `7`) while the runtime worker hashed the host. After a five-second bounded wait, the same already-loaded runtime returned:

```text
{"state":"ready","runtime_version":"0.1.0","profile_id":"steam-2026-10-19","process_id":30876}
STATUS_RETRY_EXIT=0
Responding=True
```

No reinjection occurred after the duplicate result. The game remained visibly responsive and was closed normally with `Alt+F4`.

## Persistent Timeout-State Fix

### Marker format and lifecycle

The launcher now derives a target identity under the held per-target mutex by calling `GetProcessTimes` and combining:

```text
process ID + process creation FILETIME ticks
```

The marker path is current-user-local and versioned:

```text
%LocalAppData%\MinecraftDungeonsModKit\injection-state\
	v1-<pid>-<creation_time_100ns>.state
```

The marker payload is ASCII:

```text
MCD_INJECTION_STATE_V1
pid=<decimal DWORD>
creation_time_100ns=<decimal uint64>
state=loader_started_or_uncertain
```

`CREATE_NEW` provides atomic marker existence. The complete payload is written and flushed with write-through semantics before `CreateRemoteThread`; creation, write, flush, or close failure aborts before a loader starts. A PID reused by a newer process maps to a different creation-time marker.

Lifecycle:

1. Under the PID/build mutex, inspect modules first.
2. If the exact canonical runtime is loaded, remove any matching marker and return already-loaded success.
3. If no exact module is loaded and the matching marker exists, return `injection_state_uncertain`; never start another loader.
4. Otherwise create and flush the marker immediately before `CreateRemoteThread`.
5. Remove it only after thread creation definitively fails or the loader thread definitively terminates.
6. Retain it on timeout or any wait outcome where thread completion is uncertain, alongside the existing remote-memory retention.

Old markers for exited targets are harmless and intentionally conservative; creation time prevents them from affecting a new process that reuses the PID.

### TDD evidence

Marker lifecycle tests were added before implementation for:

- fresh identity → proceed → in-progress marker → definitive cleanup;
- timeout-style retained marker surviving store reconstruction;
- exact loaded module clearing a retained marker;
- same PID with a new creation time remaining isolated;
- retained marker with no demonstrably loaded module returning `injection_state_uncertain`.

RED:

```powershell
cmake --build build --config Debug --target mcd_launcher_tests
```

Observed expected compile failures because `InjectionStateStore`, `TargetIdentity`, `InjectionStateDecision`, `evaluate_injection_state`, and `injection_state_uncertain` did not exist.

GREEN and full suite:

```powershell
cmake --build build --config Debug --target mcd_launcher_tests
.\build\tests\Debug\mcd_launcher_tests.exe
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

Observed: focused launcher test exit `0`; Debug build exit `0`; final CTest `5/5` passed, `0` failed in `0.56 sec`; launcher suite completed in `0.45 sec`.

### Safe live evidence

The exact executable inspected as profile `steam-2026-10-19`, then the game was launched to the visibly ready offline hero-selection menu. No timeout was forced:

```text
runtime injected into process 31440
INJECT_EXIT=0
{"state":"ready","runtime_version":"0.1.0","profile_id":"steam-2026-10-19","process_id":31440}
STATUS_EXIT=0
runtime already loaded into process 31440
DUPLICATE_EXIT=0
Responding=True
```

The successful definitive loader outcome left no `.state` files under the LocalAppData injection-state directory. The game remained responsive and was closed normally with `Alt+F4`.
