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
- Pipe security is a protected DACL containing only the current token's logon SID, with explicit token owner and primary-group SIDs and handle inheritance disabled.
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

- No outstanding Task 4 concerns after the review-gate follow-up below.

## Review-Gate Follow-Up

### Production Corrections

- Superseded by the process-lifetime pin decision below: the image is pinned before detached work is scheduled and intentionally remains mapped until host exit.
- Pipe security now selects the `SE_GROUP_LOGON_ID` entry from `TokenGroups`, sets owner and group from `TokenOwner` and `TokenPrimaryGroup`, and grants only generic read/write to that logon SID.
- Connect, read, write, and overlapped-wait helpers now return an `IoResult` containing both status and the originating `DWORD`; every Win32 error is captured immediately at the failing call.
- Deleted copy/move methods now carry concise ownership documentation.
- A valid status response keeps the connection alive until the client closes or shutdown cancels the wait, preventing `DisconnectNamedPipe` from discarding unread response bytes.

### Strengthened Focused Coverage

- Replaced sleep-based server readiness with `WaitNamedPipeW`/`CreateFileW` retry loops bounded by explicit deadlines.
- Added live pipe tests for byte-fragmented requests, malformed magic, oversized framing, cancellation while waiting, and cancellation while connected.
- Added descriptor inspection proving one allow ACE targets the current logon SID, owner/group match token owner/primary-group SIDs, and no owner/DACL mutation rights are granted.
- Added a focused error-result test proving a captured `DWORD` survives later last-error changes.
- Repeated the live runtime test executable three times after correcting response delivery; all runs passed.

### Follow-Up RED Evidence

Command:

```powershell
cmake --build build --config Debug --target mcd_runtime_tests
```

Observed result:

```text
runtime_tests.cpp: error C3083: 'detail': the symbol to the left of a '::' must be a type
runtime_tests.cpp: error C2039: 'build_pipe_security_descriptor': is not a member of 'mcd::runtime'
runtime_tests.cpp: error C2039: 'io_failure': is not a member of 'mcd::runtime'
```

This was the expected test-first failure because the security-descriptor and retained-error seams did not yet exist.

The new fragmented live request then exposed a second production defect: the server completed its write and immediately disconnected, allowing Windows to discard unread pipe-buffer bytes. The focused test failed at its bounded response read until the server retained the connection through client close or cancellation.

### Follow-Up GREEN Evidence

Command:

```powershell
cmake --build build --config Debug --target mcd_runtime_tests
1..3 | ForEach-Object {
	.\build\tests\Debug\mcd_runtime_tests.exe
	if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
```

Observed result:

```text
PASS pipe server stops while waiting
PASS pipe server accepts fragmented request
PASS pipe server rejects malformed frame
PASS pipe server rejects oversized frame
PASS pipe server stops while connected
PASS pipe security targets logon SID
PASS I/O failure preserves original error
```

All focused runtime tests passed in each of the three consecutive runs.

Commands:

```powershell
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure -R "runtime|protocol"
ctest --test-dir build -C Debug --output-on-failure
```

Observed result:

```text
mcd-runtime.vcxproj -> ...\build\Debug\mcd-runtime.dll
2/2 Test #4: runtime .......... Passed
100% tests passed, 0 tests failed out of 2

1/4 Test #1: smoke ............ Passed
2/4 Test #2: build_identity ... Passed
3/4 Test #3: protocol ......... Passed
4/4 Test #4: runtime .......... Passed
100% tests passed, 0 tests failed out of 4
```

## Final Gate Follow-Up: Process Pin and Cancellation

### Process-Lifetime Pin Rationale

`DllMain(DLL_PROCESS_ATTACH)` now calls:

```cpp
GetModuleHandleExW(
	GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
		GET_MODULE_HANDLE_EX_FLAG_PIN,
	reinterpret_cast<LPCWSTR>(&pin_runtime_module),
	&pinned_module);
```

before creating the detached worker. `GET_MODULE_HANDLE_EX_FLAG_PIN` makes the mapping irreversible until process termination, closing the race in which an injector could release its `LoadLibraryW` reference before the new thread acquired a temporary reference.

This is kept within the documented safe `DllMain` subset:

- it is a Kernel32 operation on an already loaded module
- it does not call `LoadLibrary`, initialize another DLL, invoke user code, allocate runtime state, or synchronize with another thread
- no caller-visible unload path remains

If worker creation fails after the irreversible pin, `DllMain` returns success with no worker, callbacks, server, or owned handles; the image is inert but safely mapped. Normal runtime shutdown stops the server, resolves or safely quarantines pending I/O state, closes runtime handles, and lets the detached worker return. Only the image mapping remains until host exit.

The implementation plan and native-runtime design now state this process-lifetime pin contract explicitly.

### Bounded Cancellation Design

- `CancelIoEx` is checked immediately and its exact `DWORD` is captured.
- `ERROR_NOT_FOUND` is accepted only as a possible completion race; the code still waits for and reads the `OVERLAPPED` result.
- Every other cancellation failure is returned unchanged after bounded completion resolution.
- Cancellation completion waits are capped at 500 ms.
- A timeout returns `ERROR_TIMEOUT`; a prior non-race cancellation error remains the primary returned error.
- Each operation owns its `OVERLAPPED` structure and transfer buffer on the heap. If the bounded wait cannot prove completion, that state is quarantined for process lifetime before the pipe handle closes, preventing kernel use-after-free without retaining an auxiliary handle, callback, or thread.
- Test-client response reads now loop until every header and payload byte is received, supporting partial byte-mode reads.

### Final Gate RED Evidence

Command:

```powershell
cmake --build build --config Debug --target mcd_runtime_tests
```

Observed result:

```text
runtime_tests.cpp: error C2039: 'resolve_cancellation':
is not a member of 'mcd::runtime::detail'
runtime_tests.cpp: error C3861: 'resolve_cancellation': identifier not found
```

This was the expected test-first failure for the missing bounded-cancellation seam.

### Final Gate Verification

Command:

```powershell
cmake --build build --config Debug --target mcd_runtime_tests mcd-runtime
ctest --test-dir build -C Debug --output-on-failure -R "runtime|protocol"
```

Observed result:

```text
mcd-runtime.vcxproj -> ...\build\Debug\mcd-runtime.dll
1/2 Test #3: protocol ... Passed
2/2 Test #4: runtime .... Passed
100% tests passed, 0 tests failed out of 2
```

Command:

```powershell
1..3 | ForEach-Object {
	.\build\tests\Debug\mcd_runtime_tests.exe
	if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

Observed result:

```text
PASS cancelled operation reports stopped
PASS cancel not found resolves completion
PASS cancel failure preserves error
PASS cancel timeout retains pending operation
```

All focused runtime tests passed in each of three consecutive runs. The full Debug suite then passed:

```text
1/4 Test #1: smoke ............ Passed
2/4 Test #2: build_identity ... Passed
3/4 Test #3: protocol ......... Passed
4/4 Test #4: runtime .......... Passed
100% tests passed, 0 tests failed out of 4
```

### Final Gate Concerns

No active handle, callback, or thread remains after runtime shutdown. In the pathological case where Windows does not resolve a cancelled operation within 500 ms, the operation's heap-only state is intentionally retained until process exit so kernel references can never outlive their storage.
