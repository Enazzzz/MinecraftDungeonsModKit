# Runtime Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and verify a native launcher and injected runtime DLL that recognize the supported Minecraft Dungeons Steam executable and exchange a versioned status message.

**Architecture:** A C++23 CMake project builds shared utility code, a command-line launcher, a Windows x64 DLL, and focused tests. The launcher verifies the executable, locates the running process, injects the DLL through `LoadLibraryW`, and then connects to a current-user local named pipe. The DLL performs minimal work in `DllMain`, initializes on a worker thread, validates its host build, starts the pipe server, and shuts down cleanly.

**Tech Stack:** C++23, CMake 3.22+, Visual Studio 2022/MSVC, Windows API, BCrypt, CTest

## Global Constraints

- Windows x64 and the current Steam build are the initial target.
- Supported SHA-256: `6A48471423B41CDCDD4F0322560DCAFAE0F433F3BC30721FAE861564A4F5CC73`.
- Supported executable size: `37,814,288` bytes.
- Source code uses tabs for indentation.
- Every function, method, and class has a concise documentation comment.
- The runtime does not bypass anti-cheat, DRM, authentication, or platform protections.
- Online and multiplayer gameplay modification is outside scope.
- Original game executables and packaged assets remain untouched.

---

## File Structure

- `CMakeLists.txt`: Defines project-wide settings and component targets.
- `cmake/compiler_options.cmake`: Centralizes warning and hardening flags.
- `include/mcd/build_identity.hpp`: Public build fingerprint types and supported profile lookup.
- `include/mcd/sha256.hpp`: Public file hashing interface.
- `include/mcd/protocol.hpp`: Versioned status request and response wire types.
- `include/mcd/wire.hpp`: Bounded byte serialization helpers.
- `src/common/build_identity.cpp`: Selects exact supported game profiles.
- `src/common/sha256_windows.cpp`: Hashes files with Windows BCrypt.
- `src/common/protocol.cpp`: Encodes and decodes control messages.
- `src/launcher/main.cpp`: Parses commands and coordinates launcher services.
- `src/launcher/process.cpp`: Finds the game process and verifies its image path.
- `include/mcd/launcher/process.hpp`: Process discovery declarations.
- `src/launcher/injector.cpp`: Performs checked `LoadLibraryW` injection.
- `include/mcd/launcher/injector.hpp`: Injector declarations and result types.
- `src/launcher/pipe_client.cpp`: Connects to the runtime and requests status.
- `include/mcd/launcher/pipe_client.hpp`: Control client declarations.
- `src/runtime/dllmain.cpp`: Starts initialization outside loader lock.
- `src/runtime/runtime.cpp`: Owns runtime initialization and shutdown.
- `include/mcd/runtime/runtime.hpp`: Runtime state and lifecycle declarations.
- `src/runtime/pipe_server.cpp`: Serves bounded control requests.
- `include/mcd/runtime/pipe_server.hpp`: Pipe server lifecycle declarations.
- `tests/build_identity_tests.cpp`: Tests exact profile acceptance and rejection.
- `tests/protocol_tests.cpp`: Tests valid and malformed wire messages.

### Task 1: Build System and Test Harness

**Files:**
- Create: `CMakeLists.txt`
- Create: `cmake/compiler_options.cmake`
- Create: `tests/CMakeLists.txt`
- Create: `src/launcher/main.cpp`
- Create: `src/runtime/dllmain.cpp`
- Create: `tests/smoke_tests.cpp`

**Interfaces:**
- Consumes: Visual Studio 2022 and CMake 3.22 or newer.
- Produces: `mcd-launcher`, `mcd-runtime`, `mcd_tests`, and `mcd_project_options`.

- [ ] **Step 1: Write the initial build definitions**

Create the root project with:

```cmake
cmake_minimum_required(VERSION 3.22)
project(MinecraftDungeonsModKit VERSION 0.1.0 LANGUAGES CXX)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
	message(FATAL_ERROR "MinecraftDungeonsModKit requires Windows x64")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(cmake/compiler_options.cmake)
add_executable(mcd-launcher src/launcher/main.cpp)
add_library(mcd-runtime SHARED src/runtime/dllmain.cpp)
set_target_properties(mcd-runtime PROPERTIES PREFIX "")

target_link_libraries(mcd-launcher PRIVATE mcd_project_options)
target_link_libraries(mcd-runtime PRIVATE mcd_project_options)

include(CTest)
if(BUILD_TESTING)
	add_subdirectory(tests)
endif()
```

Create the warnings target with `/W4`, `/permissive-`, `/EHsc`, `/utf-8`, `WIN32_LEAN_AND_MEAN`, `NOMINMAX`, and `_WIN32_WINNT=0x0A00`. Add a launcher entry point that prints `mcd-launcher 0.1.0`, a DLL entry point that only disables thread callbacks, and a smoke test that returns success after asserting `sizeof(void*) == 8`.

- [ ] **Step 2: Configure the project**

Run:

```powershell
cmake -S . -B build -A x64 -DBUILD_TESTING=ON
```

Expected: configuration succeeds and generates `build/MinecraftDungeonsModKit.sln`.

- [ ] **Step 3: Build and run the smoke test**

Run:

```powershell
cmake --build build --config Debug
```

Run:

```powershell
ctest --test-dir build -C Debug --output-on-failure
```

Expected: the build succeeds and the smoke test passes.

- [ ] **Step 4: Commit**

```powershell
git add CMakeLists.txt cmake/compiler_options.cmake src/launcher/main.cpp src/runtime/dllmain.cpp tests
git commit -m "build: add native runtime project structure"
```

### Task 2: Exact Build Identity

**Files:**
- Modify: `CMakeLists.txt`
- Modify: `cmake/compiler_options.cmake`
- Modify: `tests/CMakeLists.txt`
- Create: `include/mcd/sha256.hpp`
- Create: `include/mcd/build_identity.hpp`
- Create: `src/common/sha256_windows.cpp`
- Create: `src/common/build_identity.cpp`
- Create: `tests/build_identity_tests.cpp`

**Interfaces:**
- Consumes: `std::filesystem::path`.
- Produces: `mcd::sha256_file(const std::filesystem::path&) -> std::expected<std::array<std::byte, 32>, std::error_code>` and `mcd::identify_build(uint64_t, const Sha256Digest&) -> std::optional<BuildProfile>`.

- [ ] **Step 1: Write failing identity tests**

Add tests that decode the supported digest, accept the exact size/digest pair, reject a one-byte size difference, and reject a one-bit digest difference:

```cpp
/// Verifies that only the measured Steam executable selects the initial profile.
void test_exact_build_profile()
{
	const auto digest = mcd::parse_sha256(
		"6A48471423B41CDCDD4F0322560DCAFAE0F433F3BC30721FAE861564A4F5CC73");
	REQUIRE(digest.has_value());
	REQUIRE(mcd::identify_build(37'814'288, *digest).has_value());
	REQUIRE(!mcd::identify_build(37'814'289, *digest).has_value());
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```powershell
cmake --build build --config Debug --target mcd_tests
```

Expected: compilation fails because `mcd/build_identity.hpp` does not exist.

- [ ] **Step 3: Implement hashing and profile selection**

Define:

```cpp
namespace mcd {
using Sha256Digest = std::array<std::byte, 32>;

struct BuildProfile {
	std::string_view id;
	std::uint64_t image_size;
	Sha256Digest sha256;
};

/// Parses exactly 64 hexadecimal SHA-256 characters.
[[nodiscard]] std::optional<Sha256Digest> parse_sha256(std::string_view text);

/// Returns the profile matching both executable size and digest.
[[nodiscard]] std::optional<BuildProfile> identify_build(
	std::uint64_t image_size,
	const Sha256Digest& digest);

/// Hashes a file through the Windows BCrypt SHA-256 provider.
[[nodiscard]] std::expected<Sha256Digest, std::error_code> sha256_file(
	const std::filesystem::path& path);
}
```

Use RAII wrappers for BCrypt algorithm and hash handles. Read the file in 1 MiB chunks and propagate `GetLastError()` or translated `NTSTATUS` failures.

- [ ] **Step 4: Run identity tests**

Run:

```powershell
cmake --build build --config Debug --target mcd_tests
ctest --test-dir build -C Debug --output-on-failure -R build_identity
```

Expected: `build_identity` passes.

- [ ] **Step 5: Commit**

```powershell
git add include/mcd/sha256.hpp include/mcd/build_identity.hpp src/common/sha256_windows.cpp src/common/build_identity.cpp tests/build_identity_tests.cpp
git commit -m "feat: recognize the supported game build"
```

### Task 3: Bounded Control Protocol

**Files:**
- Modify: `CMakeLists.txt`
- Modify: `tests/CMakeLists.txt`
- Create: `include/mcd/wire.hpp`
- Create: `include/mcd/protocol.hpp`
- Create: `src/common/protocol.cpp`
- Create: `tests/protocol_tests.cpp`

**Interfaces:**
- Consumes: byte spans no larger than 64 KiB.
- Produces: `mcd::protocol::encode(const Message&) -> std::vector<std::byte>` and `mcd::protocol::decode(std::span<const std::byte>) -> std::expected<Message, ProtocolError>`.

- [ ] **Step 1: Write failing protocol tests**

Test a status request round trip, a ready response containing profile ID and runtime version, rejection of a bad magic value, rejection of a mismatched payload length, and rejection of payloads larger than 64 KiB.

```cpp
/// Verifies that a status request survives a complete wire round trip.
void test_status_round_trip()
{
	const mcd::protocol::Message request{
		.kind = mcd::protocol::MessageKind::status_request,
		.payload = {}
	};
	const auto bytes = mcd::protocol::encode(request);
	const auto decoded = mcd::protocol::decode(bytes);
	REQUIRE(decoded.has_value());
	REQUIRE(decoded->kind == request.kind);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```powershell
cmake --build build --config Debug --target mcd_tests
```

Expected: compilation fails because `mcd/protocol.hpp` does not exist.

- [ ] **Step 3: Implement the protocol**

Use this fixed little-endian header:

```cpp
struct Header {
	std::array<char, 4> magic{'M', 'C', 'D', 'R'};
	std::uint16_t version{1};
	MessageKind kind{};
	std::uint32_t payload_size{};
};
```

Encode fields explicitly instead of serializing structure memory. Set `maximum_payload_size` to `64U * 1024U`. Status responses carry UTF-8 JSON with `state`, `runtime_version`, `profile_id`, and `process_id`; the JSON values are generated by the runtime rather than accepted from clients.

- [ ] **Step 4: Run protocol tests**

Run:

```powershell
cmake --build build --config Debug --target mcd_tests
ctest --test-dir build -C Debug --output-on-failure -R protocol
```

Expected: `protocol` passes.

- [ ] **Step 5: Commit**

```powershell
git add include/mcd/wire.hpp include/mcd/protocol.hpp src/common/protocol.cpp tests/protocol_tests.cpp
git commit -m "feat: add bounded runtime control protocol"
```

### Task 4: Runtime Lifecycle and Pipe Server

**Files:**
- Modify: `CMakeLists.txt`
- Modify: `tests/CMakeLists.txt`
- Modify: `src/runtime/dllmain.cpp`
- Create: `include/mcd/runtime/runtime.hpp`
- Create: `src/runtime/runtime.cpp`
- Create: `include/mcd/runtime/pipe_server.hpp`
- Create: `src/runtime/pipe_server.cpp`

**Interfaces:**
- Consumes: host executable path and control messages from `\\.\pipe\mcd-runtime-<pid>`.
- Produces: `Runtime::start(HMODULE) -> DWORD`, `Runtime::request_stop()`, and status responses.

- [ ] **Step 1: Add lifecycle tests around a host-agnostic state machine**

Keep host-independent transitions in `RuntimeStateMachine` and test:

```cpp
/// Verifies that a build mismatch cannot transition to ready.
void test_runtime_rejects_unknown_build()
{
	mcd::runtime::RuntimeStateMachine state;
	REQUIRE(state.transition_to_validating());
	REQUIRE(state.reject_build());
	REQUIRE(state.state() == mcd::runtime::State::unsupported_build);
	REQUIRE(!state.transition_to_ready());
}
```

- [ ] **Step 2: Run the lifecycle test to verify it fails**

Run:

```powershell
cmake --build build --config Debug --target mcd_tests
```

Expected: compilation fails because `RuntimeStateMachine` is undefined.

- [ ] **Step 3: Implement runtime initialization**

`DllMain` stores its module handle, calls `DisableThreadLibraryCalls`, and starts one thread:

```cpp
/// Defers all runtime initialization until after the loader-lock callback returns.
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID)
{
	if (reason != DLL_PROCESS_ATTACH) {
		return TRUE;
	}
	DisableThreadLibraryCalls(instance);
	const HANDLE thread = CreateThread(nullptr, 0, &mcd_runtime_thread, instance, 0, nullptr);
	if (thread == nullptr) {
		return FALSE;
	}
	CloseHandle(thread);
	return TRUE;
}
```

The worker obtains the host path with `QueryFullProcessImageNameW`, hashes it, checks its size, selects the profile, and starts a one-client-at-a-time named pipe server. Pipe security uses a descriptor built for the current logon SID; remote clients are rejected with `PIPE_REJECT_REMOTE_CLIENTS`.

- [ ] **Step 4: Build and run lifecycle tests**

Run:

```powershell
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

Expected: all tests pass and `build/Debug/mcd-runtime.dll` exists.

- [ ] **Step 5: Commit**

```powershell
git add src/runtime tests
git commit -m "feat: add validated runtime lifecycle"
```

### Task 5: Process Discovery, Injection, and Status CLI

**Files:**
- Modify: `CMakeLists.txt`
- Modify: `tests/CMakeLists.txt`
- Create: `include/mcd/launcher/process.hpp`
- Create: `src/launcher/process.cpp`
- Create: `include/mcd/launcher/injector.hpp`
- Create: `src/launcher/injector.cpp`
- Create: `include/mcd/launcher/pipe_client.hpp`
- Create: `src/launcher/pipe_client.cpp`
- Modify: `src/launcher/main.cpp`

**Interfaces:**
- Consumes: `inspect <game-exe>`, `inject <game-exe> <runtime-dll>`, and `status <pid>`.
- Produces: stable process exit codes and human-readable diagnostics.

- [ ] **Step 1: Write unit tests for pure path and argument validation**

Test that injection rejects a relative DLL path, mismatched process image path, unsupported executable fingerprint, and a missing DLL before opening a remote process.

```cpp
/// Verifies that injection accepts only an absolute existing DLL path.
void test_injection_path_validation()
{
	const auto result = mcd::launcher::validate_runtime_path(L"mcd-runtime.dll");
	REQUIRE(!result.has_value());
	REQUIRE(result.error() == mcd::launcher::InjectError::runtime_path_not_absolute);
}
```

- [ ] **Step 2: Run launcher tests to verify they fail**

Run:

```powershell
cmake --build build --config Debug --target mcd_tests
```

Expected: compilation fails because `mcd/launcher/injector.hpp` does not exist.

- [ ] **Step 3: Implement process discovery and checked injection**

Enumerate processes with `CreateToolhelp32Snapshot`, then obtain and canonicalize the full image path with `QueryFullProcessImageNameW`. Open the selected process with only:

```cpp
constexpr DWORD injection_access =
	PROCESS_CREATE_THREAD |
	PROCESS_QUERY_LIMITED_INFORMATION |
	PROCESS_VM_OPERATION |
	PROCESS_VM_WRITE |
	PROCESS_VM_READ;
```

Allocate the absolute DLL path with `VirtualAllocEx`, write it with `WriteProcessMemory`, resolve local `kernel32!LoadLibraryW`, start it with `CreateRemoteThread`, wait up to 15 seconds, verify a nonzero thread exit code, and always release remote memory and handles.

- [ ] **Step 4: Implement CLI and pipe status**

Provide:

```text
mcd-launcher inspect <game-exe>
mcd-launcher inject <game-exe> <runtime-dll>
mcd-launcher status <pid>
```

`inspect` prints file size, uppercase SHA-256, and selected profile. `inject` refuses an unsupported file before finding a process, refuses a process whose canonical path differs from the inspected path, and treats an already loaded runtime module as success without injecting twice. `status` sends a protocol status request and prints the returned JSON.

- [ ] **Step 5: Run automated verification**

Run:

```powershell
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
.\build\Debug\mcd-launcher.exe inspect "C:\Program Files (x86)\Steam\steamapps\common\MinecraftDungeons\Dungeons\Binaries\Win64\Dungeons-Win64-Shipping.exe"
```

Expected: all tests pass and `inspect` reports profile `steam-2026-10-19`.

- [ ] **Step 6: Run the live integration check**

Start Minecraft Dungeons, wait for its main menu, then run:

```powershell
.\build\Debug\mcd-launcher.exe inject "C:\Program Files (x86)\Steam\steamapps\common\MinecraftDungeons\Dungeons\Binaries\Win64\Dungeons-Win64-Shipping.exe" "$PWD\build\Debug\mcd-runtime.dll"
.\build\Debug\mcd-launcher.exe status (Get-Process Dungeons-Win64-Shipping).Id
```

Expected: injection succeeds, the game remains responsive, and status prints `state: ready`, runtime version `0.1.0`, and profile `steam-2026-10-19`.

- [ ] **Step 7: Commit**

```powershell
git add src/launcher tests
git commit -m "feat: inject runtime and query status"
```

## Completion Gate

Run:

```powershell
cmake -S . -B build -A x64 -DBUILD_TESTING=ON
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
git diff --check
git status --short
```

The phase is complete when automated tests pass, the supported executable is identified exactly, live injection leaves the game responsive, the pipe reports `ready`, and no uncommitted implementation changes remain.
