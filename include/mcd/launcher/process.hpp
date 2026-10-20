#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>

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

/// Identifies one running process whose canonical image matches the requested file.
struct ProcessInfo
{
	DWORD id;
	std::filesystem::path image_path;
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

/// Returns a stable diagnostic name for one process-discovery error.
[[nodiscard]] std::string process_error_message(const ProcessFailure& failure);
}
