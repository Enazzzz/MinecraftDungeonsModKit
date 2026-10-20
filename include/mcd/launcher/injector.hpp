#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>

#include <windows.h>

#include "mcd/launcher/process.hpp"

namespace mcd::launcher
{
/// Names validation and remote-injection failure boundaries.
enum class InjectError
{
	runtime_path_not_absolute,
	runtime_not_found,
	runtime_not_regular_file,
	runtime_path_resolution_failed,
	process_image_mismatch,
	process_open_failed,
	module_snapshot_failed,
	module_query_failed,
	loader_resolution_failed,
	invalid_loader_address,
	remote_allocation_failed,
	remote_write_failed,
	remote_thread_failed,
	remote_thread_timeout,
	remote_thread_wait_failed,
	remote_load_failed,
	remote_memory_release_failed,
};

/// Carries one injection failure category and its originating Win32 error.
struct InjectFailure
{
	InjectError error;
	DWORD win32_error;
};

/// Reports whether injection loaded the runtime or found it already present.
enum class InjectionResult
{
	injected,
	already_loaded,
};

/// Validates and canonicalizes an absolute existing runtime DLL path.
[[nodiscard]] std::expected<std::filesystem::path, InjectError> validate_runtime_path(
	const std::filesystem::path& runtime_path);

/// Verifies that a process image is the same canonical path inspected by the caller.
[[nodiscard]] std::expected<void, InjectError> validate_process_image(
	const std::filesystem::path& inspected_path,
	const std::filesystem::path& process_path);

/// Derives a remote export address from local and remote module bases.
[[nodiscard]] std::expected<std::uintptr_t, InjectError> remote_export_address(
	std::uintptr_t local_module,
	std::size_t local_module_size,
	std::uintptr_t local_export,
	std::uintptr_t remote_module) noexcept;

/// Loads one validated absolute runtime DLL into the exact selected process.
[[nodiscard]] std::expected<InjectionResult, InjectFailure> inject_runtime(
	const ProcessInfo& process,
	const std::filesystem::path& inspected_path,
	const std::filesystem::path& runtime_path);

/// Returns a stable diagnostic name for one injection error.
[[nodiscard]] std::string inject_error_message(const InjectFailure& failure);
}
