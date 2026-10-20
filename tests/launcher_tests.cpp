#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>

#include "mcd/launcher/injector.hpp"
#include "mcd/launcher/process.hpp"

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
}

/// Runs launcher validation and address-derivation regression tests.
int main()
{
	test_relative_runtime_path_is_rejected();
	test_missing_runtime_is_rejected();
	test_existing_runtime_is_canonicalized();
	test_mismatched_process_image_is_rejected();
	test_process_image_comparison_is_case_insensitive();
	test_remote_export_address_uses_module_rva();
	test_invalid_local_export_address_is_rejected();
	test_out_of_range_local_export_is_rejected();
	return 0;
}
