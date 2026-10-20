#include <array>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "mcd/launcher/injector.hpp"
#include "mcd/launcher/pipe_client.hpp"
#include "mcd/launcher/process.hpp"
#include "mcd/protocol.hpp"

namespace
{
/// Throws a deterministic test failure with a human-readable message.
[[noreturn]] void fail(const std::string_view message)
{
	throw std::runtime_error(std::string(message));
}

/// Fails fast when a required test condition is false.
void require(const bool condition, const std::string_view message)
{
	if(!condition)
	{
		fail(message);
	}
}

/// Expands one active test oracle check with its source expression text.
#define REQUIRE(condition) require(static_cast<bool>(condition), #condition)

/// Owns a temporary DLL-shaped file used by validation tests.
class TemporaryRuntimeFile
{
public:
	/// Creates a unique absolute file containing deterministic test bytes.
	TemporaryRuntimeFile()
	{
		const auto suffix = std::to_wstring(
			std::chrono::steady_clock::now().time_since_epoch().count());
		path_ = std::filesystem::temp_directory_path() /
			(L"mcd-runtime-" + suffix + L".dll");
		std::ofstream stream(path_, std::ios::binary);
		stream << "runtime";
		REQUIRE(stream.good());
	}

	/// Removes the temporary file without throwing from cleanup.
	~TemporaryRuntimeFile() noexcept
	{
		std::error_code error;
		std::filesystem::remove(path_, error);
	}

	/// Prevents duplicate ownership of the temporary path.
	TemporaryRuntimeFile(const TemporaryRuntimeFile&) = delete;

	/// Prevents duplicate cleanup assignment.
	TemporaryRuntimeFile& operator=(const TemporaryRuntimeFile&) = delete;

	/// Returns the absolute temporary file path.
	[[nodiscard]] const std::filesystem::path& path() const noexcept
	{
		return path_;
	}

private:
	std::filesystem::path path_;
};

/// Owns a unique temporary root for persistent marker tests.
class TemporaryMarkerRoot
{
public:
	/// Creates an empty unique marker root path.
	TemporaryMarkerRoot()
	{
		const auto suffix = std::to_wstring(
			std::chrono::steady_clock::now().time_since_epoch().count());
		path_ = std::filesystem::temp_directory_path() /
			(L"mcd-marker-tests-" + suffix);
		std::error_code error;
		std::filesystem::remove_all(path_, error);
	}

	/// Removes all marker-test files without throwing from cleanup.
	~TemporaryMarkerRoot() noexcept
	{
		std::error_code error;
		std::filesystem::remove_all(path_, error);
	}

	/// Prevents duplicate ownership of the temporary tree.
	TemporaryMarkerRoot(const TemporaryMarkerRoot&) = delete;

	/// Prevents duplicate cleanup assignment.
	TemporaryMarkerRoot& operator=(const TemporaryMarkerRoot&) = delete;

	/// Returns the unique root path.
	[[nodiscard]] const std::filesystem::path& path() const noexcept
	{
		return path_;
	}

private:
	std::filesystem::path path_;
};

/// Verifies that injection rejects a relative runtime path.
void test_relative_runtime_path_is_rejected()
{
	const auto result = mcd::launcher::validate_runtime_path(L"mcd-runtime.dll");
	REQUIRE(!result.has_value());
	REQUIRE(result.error() == mcd::launcher::InjectError::runtime_path_not_absolute);
}

/// Verifies that injection rejects a missing absolute runtime before process access.
void test_missing_runtime_is_rejected()
{
	const auto missing = std::filesystem::temp_directory_path() /
		L"mcd-runtime-definitely-missing.dll";
	std::error_code remove_error;
	std::filesystem::remove(missing, remove_error);

	const auto result = mcd::launcher::validate_runtime_path(missing);
	REQUIRE(!result.has_value());
	REQUIRE(result.error() == mcd::launcher::InjectError::runtime_not_found);
}

/// Verifies that runtime validation returns a canonical absolute file path.
void test_existing_runtime_is_canonicalized()
{
	const TemporaryRuntimeFile runtime;
	const auto result = mcd::launcher::validate_runtime_path(runtime.path());
	REQUIRE(result.has_value());
	REQUIRE(result->is_absolute());
	REQUIRE(*result == std::filesystem::canonical(runtime.path()));
}

/// Verifies that injection accepts only the exact inspected process image.
void test_mismatched_process_image_is_rejected()
{
	const auto result = mcd::launcher::validate_process_image(
		L"C:\\Games\\Dungeons.exe",
		L"C:\\Games\\Other.exe");
	REQUIRE(!result.has_value());
	REQUIRE(result.error() == mcd::launcher::InjectError::process_image_mismatch);
}

/// Verifies that Windows-style canonical path comparison is case-insensitive.
void test_process_image_comparison_is_case_insensitive()
{
	const auto result = mcd::launcher::validate_process_image(
		L"C:\\Games\\Dungeons.exe",
		L"c:\\games\\DUNGEONS.EXE");
	REQUIRE(result.has_value());
}

/// Verifies process IDs accept only nonzero ASCII decimal digits.
void test_process_id_parser_is_strict()
{
	REQUIRE(mcd::launcher::parse_process_id(L"1") == 1U);
	REQUIRE(mcd::launcher::parse_process_id(L"4294967295") == 4'294'967'295U);
	REQUIRE(!mcd::launcher::parse_process_id(L"").has_value());
	REQUIRE(!mcd::launcher::parse_process_id(L"0").has_value());
	REQUIRE(!mcd::launcher::parse_process_id(L" 1").has_value());
	REQUIRE(!mcd::launcher::parse_process_id(L"1 ").has_value());
	REQUIRE(!mcd::launcher::parse_process_id(L"+1").has_value());
	REQUIRE(!mcd::launcher::parse_process_id(L"-1").has_value());
	REQUIRE(!mcd::launcher::parse_process_id(L"1a").has_value());
	REQUIRE(!mcd::launcher::parse_process_id(L"\u0661").has_value());
	REQUIRE(!mcd::launcher::parse_process_id(L"4294967296").has_value());
}

/// Verifies effective process architectures must match exactly.
void test_architecture_compatibility_decisions()
{
	using mcd::launcher::architectures_compatible;
	REQUIRE(architectures_compatible(
		IMAGE_FILE_MACHINE_UNKNOWN,
		IMAGE_FILE_MACHINE_AMD64,
		IMAGE_FILE_MACHINE_UNKNOWN,
		IMAGE_FILE_MACHINE_AMD64));
	REQUIRE(!architectures_compatible(
		IMAGE_FILE_MACHINE_UNKNOWN,
		IMAGE_FILE_MACHINE_AMD64,
		IMAGE_FILE_MACHINE_I386,
		IMAGE_FILE_MACHINE_AMD64));
	REQUIRE(!architectures_compatible(
		IMAGE_FILE_MACHINE_UNKNOWN,
		IMAGE_FILE_MACHINE_AMD64,
		IMAGE_FILE_MACHINE_UNKNOWN,
		IMAGE_FILE_MACHINE_ARM64));
	REQUIRE(!architectures_compatible(
		IMAGE_FILE_MACHINE_UNKNOWN,
		IMAGE_FILE_MACHINE_UNKNOWN,
		IMAGE_FILE_MACHINE_UNKNOWN,
		IMAGE_FILE_MACHINE_AMD64));
}

/// Verifies duplicate classification is monotonic and ambiguity fails closed.
void test_module_duplicate_classification()
{
	using mcd::launcher::ModuleMatch;
	using mcd::launcher::classify_runtime_module;
	using mcd::launcher::merge_module_match;

	const std::filesystem::path runtime = L"C:\\Kit\\mcd-runtime.dll";
	REQUIRE(classify_runtime_module(
		runtime,
		L"C:\\Windows\\System32\\kernel32.dll") == ModuleMatch::none);
	REQUIRE(classify_runtime_module(
		runtime,
		L"c:\\kit\\MCD-RUNTIME.DLL") == ModuleMatch::exact);
	REQUIRE(classify_runtime_module(
		runtime,
		L"C:\\Other\\mcd-runtime.dll") == ModuleMatch::ambiguous);
	REQUIRE(merge_module_match(ModuleMatch::exact, ModuleMatch::none) == ModuleMatch::exact);
	REQUIRE(merge_module_match(
		ModuleMatch::exact,
		ModuleMatch::ambiguous) == ModuleMatch::ambiguous);
	REQUIRE(merge_module_match(
		ModuleMatch::ambiguous,
		ModuleMatch::exact) == ModuleMatch::ambiguous);
}

/// Verifies that remote exports are derived by RVA instead of reusing local pointers.
void test_remote_export_address_uses_module_rva()
{
	const auto result = mcd::launcher::remote_export_address(
		0x00007FFA'10000000ULL,
		0x00200000ULL,
		0x00007FFA'10012340ULL,
		0x00007FFB'20000000ULL);
	REQUIRE(result.has_value());
	REQUIRE(*result == 0x00007FFB'20012340ULL);
}

/// Verifies that an export outside its local module is rejected.
void test_invalid_local_export_address_is_rejected()
{
	const auto result = mcd::launcher::remote_export_address(
		0x00007FFA'10000000ULL,
		0x00200000ULL,
		0x00007FFA'0FFFFFFFULL,
		0x00007FFB'20000000ULL);
	REQUIRE(!result.has_value());
	REQUIRE(result.error() == mcd::launcher::InjectError::invalid_loader_address);
}

/// Verifies that an export beyond the local image extent is rejected.
void test_out_of_range_local_export_is_rejected()
{
	const auto result = mcd::launcher::remote_export_address(
		0x00007FFA'10000000ULL,
		0x00200000ULL,
		0x00007FFA'10200000ULL,
		0x00007FFB'20000000ULL);
	REQUIRE(!result.has_value());
	REQUIRE(result.error() == mcd::launcher::InjectError::invalid_loader_address);
}

/// Reads one complete status request from a connected test pipe.
void read_status_request(const HANDLE pipe)
{
	std::array<std::byte, mcd::protocol::header_size> request {};
	std::size_t offset = 0U;
	while(offset < request.size())
	{
		DWORD transferred = 0U;
		REQUIRE(ReadFile(
			pipe,
			request.data() + offset,
			static_cast<DWORD>(request.size() - offset),
			&transferred,
			nullptr));
		REQUIRE(transferred > 0U);
		offset += transferred;
	}
	const auto decoded = mcd::protocol::decode(request);
	REQUIRE(decoded.has_value());
	REQUIRE(decoded->kind == mcd::protocol::MessageKind::status_request);
}

/// Creates one byte-mode test status pipe for a synthetic process ID.
HANDLE create_test_pipe(const DWORD process_id)
{
	const std::wstring name =
		L"\\\\.\\pipe\\mcd-runtime-" + std::to_wstring(process_id);
	return CreateNamedPipeW(
		name.c_str(),
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
		1U,
		4'096U,
		4'096U,
		0U,
		nullptr);
}

/// Verifies the launcher client assembles a response split across partial reads.
void test_pipe_client_accepts_fragmented_response()
{
	const DWORD process_id = GetCurrentProcessId();
	const HANDLE pipe = create_test_pipe(process_id);
	REQUIRE(pipe != INVALID_HANDLE_VALUE);
	auto server = std::async(std::launch::async, [pipe] {
		REQUIRE(ConnectNamedPipe(pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED);
		read_status_request(pipe);
		const std::string payload = "{\"state\":\"ready\"}";
		const auto payload_chars = std::span {payload.data(), payload.size()};
		const auto payload_bytes = std::as_bytes(payload_chars);
		const auto response = mcd::protocol::encode({
			.kind = mcd::protocol::MessageKind::status_response,
			.payload = std::vector<std::byte>(payload_bytes.begin(), payload_bytes.end()),
		});
		DWORD transferred = 0U;
		REQUIRE(WriteFile(pipe, response.data(), 3U, &transferred, nullptr));
		REQUIRE(transferred == 3U);
		std::this_thread::sleep_for(std::chrono::milliseconds(30));
		REQUIRE(WriteFile(
			pipe,
			response.data() + 3U,
			static_cast<DWORD>(response.size() - 3U),
			&transferred,
			nullptr));
		CloseHandle(pipe);
	});

	const auto result = mcd::launcher::detail::query_status(process_id, 1'000U);
	REQUIRE(result.has_value());
	REQUIRE(*result == "{\"state\":\"ready\"}");
	server.get();
}

/// Verifies the launcher client returns after its bounded response deadline.
void test_pipe_client_times_out()
{
	const DWORD process_id = GetCurrentProcessId();
	const HANDLE pipe = create_test_pipe(process_id);
	REQUIRE(pipe != INVALID_HANDLE_VALUE);
	auto server = std::async(std::launch::async, [pipe] {
		REQUIRE(ConnectNamedPipe(pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED);
		read_status_request(pipe);
		std::this_thread::sleep_for(std::chrono::milliseconds(250));
		CloseHandle(pipe);
	});

	const auto started = std::chrono::steady_clock::now();
	const auto result = mcd::launcher::detail::query_status(process_id, 100U);
	const auto elapsed = std::chrono::steady_clock::now() - started;
	REQUIRE(!result.has_value());
	REQUIRE(result.error().error == mcd::launcher::PipeClientError::timeout);
	REQUIRE(elapsed < std::chrono::seconds(1));
	server.get();
}

/// Verifies an impostor PID cannot satisfy exact pipe-server authentication.
void test_pipe_client_rejects_server_pid_mismatch()
{
	REQUIRE(mcd::launcher::detail::server_process_matches(123U, 123U));
	REQUIRE(!mcd::launcher::detail::server_process_matches(123U, 124U));
	REQUIRE(!mcd::launcher::detail::server_process_matches(0U, 0U));
}

/// Verifies two launcher contenders cannot enter one target critical section.
void test_injection_lock_serializes_contenders()
{
	auto first = mcd::launcher::TargetInjectionLock::acquire(
		12345U,
		L"steam-2026-10-19",
		1'000U);
	REQUIRE(first.has_value());

	auto second = std::async(std::launch::async, [] {
		return mcd::launcher::TargetInjectionLock::acquire(
			12345U,
			L"steam-2026-10-19",
			100U);
	});
	const auto blocked = second.get();
	REQUIRE(!blocked.has_value());
	REQUIRE(blocked.error().error == mcd::launcher::InjectError::synchronization_timeout);
}

/// Verifies a fresh identity can enter progress and clean up definitively.
void test_injection_marker_definitive_lifecycle()
{
	const TemporaryMarkerRoot root;
	mcd::launcher::detail::InjectionStateStore store(root.path());
	const mcd::launcher::detail::TargetIdentity identity {
		.process_id = 12345U,
		.creation_time = 100U,
	};

	const auto fresh = mcd::launcher::detail::evaluate_injection_state(
		store,
		identity,
		mcd::launcher::ModuleMatch::none);
	REQUIRE(fresh == mcd::launcher::detail::InjectionStateDecision::proceed);
	REQUIRE(store.create(identity).has_value());
	REQUIRE(store.exists(identity).value());
	REQUIRE(store.clear(identity).has_value());
	REQUIRE(!store.exists(identity).value());
}

/// Verifies a timeout-style retained marker survives store reconstruction.
void test_injection_marker_timeout_is_retained()
{
	const TemporaryMarkerRoot root;
	const mcd::launcher::detail::TargetIdentity identity {
		.process_id = 12345U,
		.creation_time = 200U,
	};
	{
		mcd::launcher::detail::InjectionStateStore store(root.path());
		REQUIRE(store.create(identity).has_value());
	}
	mcd::launcher::detail::InjectionStateStore reopened(root.path());
	REQUIRE(reopened.exists(identity).value());
}

/// Verifies an exact loaded module clears a retained marker as stale.
void test_exact_module_clears_injection_marker()
{
	const TemporaryMarkerRoot root;
	mcd::launcher::detail::InjectionStateStore store(root.path());
	const mcd::launcher::detail::TargetIdentity identity {
		.process_id = 12345U,
		.creation_time = 300U,
	};
	REQUIRE(store.create(identity).has_value());

	const auto result = mcd::launcher::detail::evaluate_injection_state(
		store,
		identity,
		mcd::launcher::ModuleMatch::exact);
	REQUIRE(result == mcd::launcher::detail::InjectionStateDecision::already_loaded);
	REQUIRE(!store.exists(identity).value());
}

/// Verifies PID reuse receives a distinct creation-time marker identity.
void test_new_process_creation_time_is_isolated()
{
	const TemporaryMarkerRoot root;
	mcd::launcher::detail::InjectionStateStore store(root.path());
	const mcd::launcher::detail::TargetIdentity old_identity {
		.process_id = 12345U,
		.creation_time = 400U,
	};
	const mcd::launcher::detail::TargetIdentity new_identity {
		.process_id = 12345U,
		.creation_time = 401U,
	};
	REQUIRE(store.create(old_identity).has_value());

	const auto result = mcd::launcher::detail::evaluate_injection_state(
		store,
		new_identity,
		mcd::launcher::ModuleMatch::none);
	REQUIRE(result == mcd::launcher::detail::InjectionStateDecision::proceed);
	REQUIRE(store.exists(old_identity).value());
	REQUIRE(!store.exists(new_identity).value());
}

/// Verifies uncertainty without an exact module refuses another loader.
void test_uncertain_marker_refuses_retry()
{
	const TemporaryMarkerRoot root;
	mcd::launcher::detail::InjectionStateStore store(root.path());
	const mcd::launcher::detail::TargetIdentity identity {
		.process_id = 12345U,
		.creation_time = 500U,
	};
	REQUIRE(store.create(identity).has_value());

	const auto result = mcd::launcher::detail::evaluate_injection_state(
		store,
		identity,
		mcd::launcher::ModuleMatch::none);
	REQUIRE(!result.has_value());
	REQUIRE(result.error().error == mcd::launcher::InjectError::injection_state_uncertain);
	REQUIRE(store.exists(identity).value());
}

/// Runs one named test while reporting its diagnostic boundary.
void run_test(const std::string_view name, void (*test)())
{
	std::cout << "RUN " << name << '\n';
	test();
	std::cout << "PASS " << name << '\n';
}
}

/// Runs launcher validation and address-derivation regression tests.
int main()
{
	std::cout << std::unitbuf;
	run_test("relative runtime path is rejected", &test_relative_runtime_path_is_rejected);
	run_test("missing runtime is rejected", &test_missing_runtime_is_rejected);
	run_test("existing runtime is canonicalized", &test_existing_runtime_is_canonicalized);
	run_test("mismatched process image is rejected", &test_mismatched_process_image_is_rejected);
	run_test(
		"process image comparison is case insensitive",
		&test_process_image_comparison_is_case_insensitive);
	run_test("process ID parser is strict", &test_process_id_parser_is_strict);
	run_test("architecture compatibility decisions", &test_architecture_compatibility_decisions);
	run_test("module duplicate classification", &test_module_duplicate_classification);
	run_test("remote export address uses module RVA", &test_remote_export_address_uses_module_rva);
	run_test("invalid local export is rejected", &test_invalid_local_export_address_is_rejected);
	run_test("out of range local export is rejected", &test_out_of_range_local_export_is_rejected);
	run_test("pipe client accepts fragmented response", &test_pipe_client_accepts_fragmented_response);
	run_test("pipe client times out", &test_pipe_client_times_out);
	run_test("pipe client rejects server PID mismatch", &test_pipe_client_rejects_server_pid_mismatch);
	run_test("injection lock serializes contenders", &test_injection_lock_serializes_contenders);
	run_test("injection marker definitive lifecycle", &test_injection_marker_definitive_lifecycle);
	run_test("injection marker timeout is retained", &test_injection_marker_timeout_is_retained);
	run_test("exact module clears injection marker", &test_exact_module_clears_injection_marker);
	run_test("new process creation time is isolated", &test_new_process_creation_time_is_isolated);
	run_test("uncertain marker refuses retry", &test_uncertain_marker_refuses_retry);
	return 0;
}
