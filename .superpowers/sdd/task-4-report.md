# Task 4 Report: Runtime Lifecycle and Pipe Server

## Scope Delivered

Implemented the injected runtime bootstrap and local control server:

- loader-lock callback work is limited to disabling thread callbacks and starting one worker
- host validation queries the executable path, checks its file size and SHA-256, and selects an exact build profile
- `RuntimeStateMachine` keeps lifecycle transitions host-independent and atomic
- the pipe server accepts one client at a time at `\\.\pipe\mcd-runtime-<pid>`
- a protected DACL grants access only to the current process user's SID
- `PIPE_REJECT_REMOTE_CLIENTS` rejects non-local clients
- overlapped connection, read, and write operations are cancellable through a stop event
- frame payload allocation is capped at the protocol's 64 KiB maximum
- Windows handles and local security allocations use RAII wrappers

No Unreal hooks or launcher injection were added.

## Files Changed

- Modified `CMakeLists.txt`
- Modified `tests/CMakeLists.txt`
- Modified `src/runtime/dllmain.cpp`
- Created `include/mcd/runtime/runtime.hpp`
- Created `src/runtime/runtime.cpp`
- Created `include/mcd/runtime/pipe_server.hpp`
- Created `src/runtime/pipe_server.cpp`
- Created `tests/runtime_tests.cpp`

## RED Evidence

The lifecycle test and its build target were added before the runtime interface.

Command:

```powershell
cmake -S . -B build
cmake --build build --config Debug --target mcd_tests
```

Observed failure:

```text
runtime_tests.cpp(5,10): error C1083: Cannot open include file:
'mcd/runtime/runtime.hpp': No such file or directory
```

This was the expected failure because the requested state-machine API did not yet exist.

## GREEN Evidence

### Focused lifecycle build

Command:

```powershell
cmake --build build --config Debug --target mcd_tests
```

Observed result:

```text
mcd-runtime-core.vcxproj -> ...\build\Debug\mcd-runtime-core.lib
mcd_runtime_tests.vcxproj -> ...\build\tests\Debug\mcd_runtime_tests.exe
```

### Focused lifecycle and pipe-shutdown test

Command:

```powershell
ctest --test-dir build -C Debug --output-on-failure -R runtime
```

Observed result:

```text
1/1 Test #4: runtime ... Passed
100% tests passed, 0 tests failed out of 1
```

The focused test covers unknown-build rejection, the successful ready transition, idempotent stop requests, failure unwinding, and cancellation while the server is waiting for a client.

### Full build and suite

Commands:

```powershell
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

Observed result:

```text
mcd-runtime.vcxproj -> ...\build\Debug\mcd-runtime.dll
1/4 Test #1: smoke ............ Passed
2/4 Test #2: build_identity ... Passed
3/4 Test #3: protocol ......... Passed
4/4 Test #4: runtime .......... Passed
100% tests passed, 0 tests failed out of 4
```

## Design Notes

- Runtime initialization runs on a worker created during process attach; hashing, profile selection, security setup, and pipe I/O do not run in `DllMain`.
- Lifecycle transitions use compare-and-exchange operations so invalid or repeated transitions are rejected deterministically.
- Pipe security is a protected DACL containing only the current token user's SID, with handle inheritance disabled.
- Every server I/O operation is overlapped and waits on both its completion event and the shared stop event. Cancellation waits for completion before the stack-owned `OVERLAPPED` object is released.
- The server reads the fixed header first, rejects a declared payload over 64 KiB, and only then allocates and reads the payload.
- Malformed requests are disconnected without a response; valid empty `status_request` messages receive a bounded `status_response`.

## Self-Review

- Confirmed the loader-lock callback performs no host inspection, hashing, security allocation, or pipe I/O.
- Confirmed all runtime-owned Windows handles and security descriptors have deterministic RAII cleanup.
- Confirmed stop requests cancel both a pending connection and pending client I/O.
- Confirmed unsupported builds cannot transition to ready.
- Confirmed initialization and server failures unwind to terminal lifecycle states.
- Confirmed new code uses tabs and concise documentation comments for functions, methods, and classes.
- Confirmed `git diff --check` reports no whitespace errors.

## Concerns

- The test suite exercises the real Windows pipe creation/security path and pending-connect cancellation, while detailed malformed-frame behavior remains covered at the transport-independent protocol layer rather than through a second live pipe client.
