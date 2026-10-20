#include <array>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <future>
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
	constexpr DWORD process_id = 4'000'000'001U;
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
	constexpr DWORD process_id = 4'000'000'002U;
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
}

/// Runs launcher validation and address-derivation regression tests.
int main()
{
	test_relative_runtime_path_is_rejected();
	test_missing_runtime_is_rejected();
	test_existing_runtime_is_canonicalized();
	test_mismatched_process_image_is_rejected();
	test_process_image_comparison_is_case_insensitive();
	test_process_id_parser_is_strict();
	test_architecture_compatibility_decisions();
	test_module_duplicate_classification();
	test_remote_export_address_uses_module_rva();
	test_invalid_local_export_address_is_rejected();
	test_out_of_range_local_export_is_rejected();
	test_pipe_client_accepts_fragmented_response();
	test_pipe_client_times_out();
	test_injection_lock_serializes_contenders();
	return 0;
}
