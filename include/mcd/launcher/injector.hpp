#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>

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
	process_time_query_failed,
	architecture_query_failed,
	architecture_mismatch,
	synchronization_failed,
	synchronization_timeout,
	module_snapshot_failed,
	module_query_failed,
	module_ambiguous,
	injection_state_root_failed,
	injection_state_query_failed,
	injection_state_create_failed,
	injection_state_write_failed,
	injection_state_cleanup_failed,
	injection_state_uncertain,
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

/// Classifies one remote module relative to the requested runtime path.
enum class ModuleMatch
{
	none,
	exact,
	ambiguous,
};

namespace detail
{
/// Identifies one live process independently of PID reuse.
struct TargetIdentity
{
	DWORD process_id;
	std::uint64_t creation_time;
};

/// Names the safe action after reconciling marker and module state.
enum class InjectionStateDecision
{
	proceed,
	already_loaded,
};

/// Persists versioned fail-closed loader state below a caller-selected root.
class InjectionStateStore
{
public:
	/// Records the injection-state directory used by this store.
	explicit InjectionStateStore(std::filesystem::path root);

	/// Resolves the current user's LocalAppData injection-state directory.
	[[nodiscard]] static std::expected<InjectionStateStore, InjectFailure> current_user();

	/// Returns the versioned marker path for one PID/creation-time identity.
	[[nodiscard]] std::filesystem::path marker_path(
		const TargetIdentity& identity) const;

	/// Returns whether one identity has retained uncertain loader state.
	[[nodiscard]] std::expected<bool, InjectFailure> exists(
		const TargetIdentity& identity) const;

	/// Atomically creates and durably writes one in-progress identity marker.
	[[nodiscard]] std::expected<void, InjectFailure> create(
		const TargetIdentity& identity) const;

	/// Removes one marker after loader completion is definitive.
	[[nodiscard]] std::expected<void, InjectFailure> clear(
		const TargetIdentity& identity) const;

private:
	std::filesystem::path root_;
};

/// Reconciles persisted state with the currently observed module set.
[[nodiscard]] std::expected<InjectionStateDecision, InjectFailure>
evaluate_injection_state(
	const InjectionStateStore& store,
	const TargetIdentity& identity,
	ModuleMatch module_match);
}

/// Owns a bounded per-target launcher injection critical section.
class TargetInjectionLock
{
public:
	/// Releases the mutex when owned and closes its kernel handle.
	~TargetInjectionLock() noexcept;

	/// Prevents duplicate ownership of one mutex acquisition.
	TargetInjectionLock(const TargetInjectionLock&) = delete;

	/// Prevents duplicate assignment of one mutex acquisition.
	TargetInjectionLock& operator=(const TargetInjectionLock&) = delete;

	/// Transfers one mutex acquisition.
	TargetInjectionLock(TargetInjectionLock&& other) noexcept;

	/// Replaces this lock with a transferred mutex acquisition.
	TargetInjectionLock& operator=(TargetInjectionLock&& other) noexcept;

	/// Acquires the target/build mutex before a bounded deadline.
	[[nodiscard]] static std::expected<TargetInjectionLock, InjectFailure> acquire(
		DWORD process_id,
		std::wstring_view build_id,
		DWORD timeout_ms);

private:
	/// Records ownership of one successfully acquired mutex.
	explicit TargetInjectionLock(HANDLE mutex) noexcept;

	HANDLE mutex_;
};

/// Validates and canonicalizes an absolute existing runtime DLL path.
[[nodiscard]] std::expected<std::filesystem::path, InjectError> validate_runtime_path(
	const std::filesystem::path& runtime_path);

/// Verifies that a process image is the same canonical path inspected by the caller.
[[nodiscard]] std::expected<void, InjectError> validate_process_image(
	const std::filesystem::path& inspected_path,
	const std::filesystem::path& process_path);

/// Returns whether launcher and target effective machine types match.
[[nodiscard]] bool architectures_compatible(
	USHORT launcher_process_machine,
	USHORT launcher_native_machine,
	USHORT target_process_machine,
	USHORT target_native_machine) noexcept;

/// Classifies one canonical module path without forgetting prior matches.
[[nodiscard]] ModuleMatch classify_runtime_module(
	const std::filesystem::path& runtime_path,
	const std::filesystem::path& module_path) noexcept;

/// Merges one module observation with ambiguity taking precedence.
[[nodiscard]] ModuleMatch merge_module_match(
	ModuleMatch current,
	ModuleMatch observed) noexcept;

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
	std::wstring_view build_id,
	const std::filesystem::path& runtime_path);

/// Returns a stable diagnostic name for one injection error.
[[nodiscard]] std::string inject_error_message(const InjectFailure& failure);
}
