#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

#include <windows.h>

namespace mcd::launcher
{
/// Names process-discovery failures that are safe to expose to the CLI.
enum class ProcessError
{
	snapshot_failed,
	query_failed,
	not_found,
	multiple_matches,
};

/// Identifies one discovered process candidate by its inherently reusable PID.
struct ProcessInfo
{
	DWORD id;
};

/// Carries one process failure category and its originating Win32 error.
struct ProcessFailure
{
	ProcessError error;
	DWORD win32_error;
};

/// Locates exactly one process whose canonical image is the requested executable.
[[nodiscard]] std::expected<ProcessInfo, ProcessFailure> find_process(
	const std::filesystem::path& executable_path);

/// Returns the canonical image path of one process opened for limited query access.
[[nodiscard]] std::expected<std::filesystem::path, ProcessFailure> process_image_path(
	DWORD process_id);

/// Parses one nonzero process ID from strict ASCII decimal text.
[[nodiscard]] std::optional<DWORD> parse_process_id(std::wstring_view text) noexcept;

/// Returns a stable diagnostic name for one process-discovery error.
[[nodiscard]] std::string process_error_message(const ProcessFailure& failure);
}
