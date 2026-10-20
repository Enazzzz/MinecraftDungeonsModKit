#include "mcd/launcher/injector.hpp"

#include <limits>
#include <string>
#include <utility>
#include <vector>

#include <shlobj.h>
#include <tlhelp32.h>

namespace
{
constexpr DWORD injection_access =
	PROCESS_CREATE_THREAD |
	PROCESS_QUERY_LIMITED_INFORMATION |
	PROCESS_VM_OPERATION |
	PROCESS_VM_WRITE |
	PROCESS_VM_READ;
constexpr DWORD injection_timeout_ms = 15'000U;
constexpr DWORD synchronization_timeout_ms = 15'000U;

/// Owns one closeable Windows kernel handle.
class UniqueHandle
{
public:
	/// Takes ownership of a possibly invalid handle.
	explicit UniqueHandle(const HANDLE handle = nullptr) noexcept
		: handle_(handle)
	{
	}

	/// Closes the owned handle when valid.
	~UniqueHandle() noexcept
	{
		if(valid())
		{
			CloseHandle(handle_);
		}
	}

	/// Prevents duplicating kernel-handle ownership.
	UniqueHandle(const UniqueHandle&) = delete;

	/// Prevents duplicate ownership through assignment.
	UniqueHandle& operator=(const UniqueHandle&) = delete;

	/// Transfers kernel-handle ownership.
	UniqueHandle(UniqueHandle&& other) noexcept
		: handle_(std::exchange(other.handle_, nullptr))
	{
	}

	/// Replaces this wrapper with transferred ownership.
	UniqueHandle& operator=(UniqueHandle&& other) noexcept
	{
		if(this != &other)
		{
			if(valid())
			{
				CloseHandle(handle_);
			}
			handle_ = std::exchange(other.handle_, nullptr);
		}
		return *this;
	}

	/// Returns the owned raw handle.
	[[nodiscard]] HANDLE get() const noexcept
	{
		return handle_;
	}

	/// Returns whether this wrapper owns a usable handle.
	[[nodiscard]] bool valid() const noexcept
	{
		return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
	}

private:
	HANDLE handle_;
};

/// Owns one allocation in a remote process after its worker has completed.
class RemoteAllocation
{
public:
	/// Records a process and its possibly null remote allocation.
	RemoteAllocation(const HANDLE process, void* address) noexcept
		: process_(process),
		  address_(address)
	{
	}

	/// Releases completed-operation storage unless ownership was abandoned.
	~RemoteAllocation() noexcept
	{
		if(address_)
		{
			VirtualFreeEx(process_, address_, 0U, MEM_RELEASE);
		}
	}

	/// Prevents duplicate remote-allocation ownership.
	RemoteAllocation(const RemoteAllocation&) = delete;

	/// Prevents duplicate cleanup assignment.
	RemoteAllocation& operator=(const RemoteAllocation&) = delete;

	/// Returns the remote base address.
	[[nodiscard]] void* get() const noexcept
	{
		return address_;
	}

	/// Releases the remote allocation and reports the originating failure.
	[[nodiscard]] DWORD release() noexcept
	{
		if(address_ && !VirtualFreeEx(process_, address_, 0U, MEM_RELEASE))
		{
			return GetLastError();
		}
		address_ = nullptr;
		return ERROR_SUCCESS;
	}

	/// Abandons storage that a timed-out remote thread may still reference.
	void abandon() noexcept
	{
		address_ = nullptr;
	}

private:
	HANDLE process_;
	void* address_;
};

/// Compares Windows paths using ordinal case-insensitive semantics.
bool equal_windows_path(
	const std::filesystem::path& left,
	const std::filesystem::path& right) noexcept
{
	return CompareStringOrdinal(
			   left.c_str(),
			   -1,
			   right.c_str(),
			   -1,
			   TRUE) == CSTR_EQUAL;
}

/// Returns one canonical image path from the exact held process handle.
std::expected<std::filesystem::path, mcd::launcher::InjectFailure> held_process_image_path(
	const HANDLE process)
{
	std::vector<wchar_t> buffer(32'768U);
	DWORD length = static_cast<DWORD>(buffer.size());
	if(!QueryFullProcessImageNameW(process, 0U, buffer.data(), &length))
	{
		return std::unexpected(mcd::launcher::InjectFailure {
			.error = mcd::launcher::InjectError::process_image_mismatch,
			.win32_error = GetLastError(),
		});
	}

	std::error_code canonical_error;
	const auto canonical = std::filesystem::canonical(
		std::filesystem::path(std::wstring_view(buffer.data(), length)),
		canonical_error);
	if(canonical_error)
	{
		return std::unexpected(mcd::launcher::InjectFailure {
			.error = mcd::launcher::InjectError::process_image_mismatch,
			.win32_error = static_cast<DWORD>(canonical_error.value()),
		});
	}
	return canonical;
}

/// Verifies the held target has the same effective machine as the launcher.
std::expected<void, mcd::launcher::InjectFailure> validate_architecture(
	const HANDLE target)
{
	USHORT launcher_process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
	USHORT launcher_native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
	if(!IsWow64Process2(
		   GetCurrentProcess(),
		   &launcher_process_machine,
		   &launcher_native_machine))
	{
		return std::unexpected(mcd::launcher::InjectFailure {
			.error = mcd::launcher::InjectError::architecture_query_failed,
			.win32_error = GetLastError(),
		});
	}

	USHORT target_process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
	USHORT target_native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
	if(!IsWow64Process2(
		   target,
		   &target_process_machine,
		   &target_native_machine))
	{
		return std::unexpected(mcd::launcher::InjectFailure {
			.error = mcd::launcher::InjectError::architecture_query_failed,
			.win32_error = GetLastError(),
		});
	}
	if(!mcd::launcher::architectures_compatible(
		   launcher_process_machine,
		   launcher_native_machine,
		   target_process_machine,
		   target_native_machine))
	{
		return std::unexpected(mcd::launcher::InjectFailure {
			.error = mcd::launcher::InjectError::architecture_mismatch,
			.win32_error = ERROR_BAD_EXE_FORMAT,
		});
	}
	return {};
}

/// Derives a PID-reuse-safe identity from the exact held process handle.
std::expected<mcd::launcher::detail::TargetIdentity, mcd::launcher::InjectFailure>
target_identity(const HANDLE target)
{
	FILETIME creation {};
	FILETIME exit {};
	FILETIME kernel {};
	FILETIME user {};
	if(!GetProcessTimes(target, &creation, &exit, &kernel, &user))
	{
		return std::unexpected(mcd::launcher::InjectFailure {
			.error = mcd::launcher::InjectError::process_time_query_failed,
			.win32_error = GetLastError(),
		});
	}
	const DWORD process_id = GetProcessId(target);
	if(process_id == 0U)
	{
		return std::unexpected(mcd::launcher::InjectFailure {
			.error = mcd::launcher::InjectError::process_time_query_failed,
			.win32_error = GetLastError(),
		});
	}
	const std::uint64_t creation_time =
		(static_cast<std::uint64_t>(creation.dwHighDateTime) << 32U) |
		creation.dwLowDateTime;
	return mcd::launcher::detail::TargetIdentity {
		.process_id = process_id,
		.creation_time = creation_time,
	};
}

/// Returns the mapped size recorded by one trusted local PE image.
std::expected<std::size_t, DWORD> module_image_size(const HMODULE module) noexcept
{
	const auto* base = reinterpret_cast<const std::byte*>(module);
	const auto* dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
	if(!dos_header || dos_header->e_magic != IMAGE_DOS_SIGNATURE || dos_header->e_lfanew <= 0)
	{
		return std::unexpected(ERROR_BAD_EXE_FORMAT);
	}
	const auto* nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
		base + dos_header->e_lfanew);
	if(nt_headers->Signature != IMAGE_NT_SIGNATURE ||
	   nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
	   nt_headers->OptionalHeader.SizeOfImage == 0U)
	{
		return std::unexpected(ERROR_BAD_EXE_FORMAT);
	}
	return nt_headers->OptionalHeader.SizeOfImage;
}

/// Creates a module snapshot while tolerating the documented transient race.
std::expected<UniqueHandle, DWORD> module_snapshot(const DWORD process_id)
{
	for(unsigned int attempt = 0U; attempt < 4U; ++attempt)
	{
		UniqueHandle snapshot(CreateToolhelp32Snapshot(
			TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
			process_id));
		if(snapshot.valid())
		{
			return snapshot;
		}
		const DWORD error = GetLastError();
		if(error != ERROR_BAD_LENGTH)
		{
			return std::unexpected(error);
		}
	}
	return std::unexpected(ERROR_BAD_LENGTH);
}

/// Enumerates modules to detect duplicates and locate remote kernel32.
std::expected<std::pair<mcd::launcher::ModuleMatch, std::uintptr_t>, mcd::launcher::InjectFailure>
inspect_modules(
	const HANDLE process,
	const std::filesystem::path& runtime_path)
{
	const DWORD process_id = GetProcessId(process);
	if(process_id == 0U)
	{
		return std::unexpected(mcd::launcher::InjectFailure {
			.error = mcd::launcher::InjectError::module_snapshot_failed,
			.win32_error = GetLastError(),
		});
	}
	auto snapshot = module_snapshot(process_id);
	if(!snapshot)
	{
		return std::unexpected(mcd::launcher::InjectFailure {
			.error = mcd::launcher::InjectError::module_snapshot_failed,
			.win32_error = snapshot.error(),
		});
	}

	mcd::launcher::ModuleMatch runtime_match = mcd::launcher::ModuleMatch::none;
	std::uintptr_t kernel32_base = 0U;
	MODULEENTRY32W entry {.dwSize = sizeof(MODULEENTRY32W)};
	if(!Module32FirstW(snapshot->get(), &entry))
	{
		return std::unexpected(mcd::launcher::InjectFailure {
			.error = mcd::launcher::InjectError::module_query_failed,
			.win32_error = GetLastError(),
		});
	}
	do
	{
		if(_wcsicmp(entry.szModule, L"kernel32.dll") == 0)
		{
			kernel32_base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
		}

		if(_wcsicmp(entry.szModule, runtime_path.filename().c_str()) == 0)
		{
			std::error_code path_error;
			const auto module_path =
				std::filesystem::canonical(entry.szExePath, path_error);
			if(path_error)
			{
				return std::unexpected(mcd::launcher::InjectFailure {
					.error = mcd::launcher::InjectError::module_query_failed,
					.win32_error = static_cast<DWORD>(path_error.value()),
				});
			}
			runtime_match = mcd::launcher::merge_module_match(
				runtime_match,
				mcd::launcher::classify_runtime_module(runtime_path, module_path));
		}
	}
	while(Module32NextW(snapshot->get(), &entry));

	const DWORD enumeration_error = GetLastError();
	if(enumeration_error != ERROR_NO_MORE_FILES)
	{
		return std::unexpected(mcd::launcher::InjectFailure {
			.error = mcd::launcher::InjectError::module_query_failed,
			.win32_error = enumeration_error,
		});
	}
	if(kernel32_base == 0U)
	{
		return std::unexpected(mcd::launcher::InjectFailure {
			.error = mcd::launcher::InjectError::loader_resolution_failed,
			.win32_error = ERROR_MOD_NOT_FOUND,
		});
	}
	return std::pair {runtime_match, kernel32_base};
}
}

namespace mcd::launcher::detail
{
/// Records the injection-state directory used by this store.
InjectionStateStore::InjectionStateStore(std::filesystem::path root)
	: root_(std::move(root))
{
}

/// Resolves the current user's LocalAppData injection-state directory.
std::expected<InjectionStateStore, InjectFailure> InjectionStateStore::current_user()
{
	PWSTR raw_path = nullptr;
	const HRESULT result = SHGetKnownFolderPath(
		FOLDERID_LocalAppData,
		KF_FLAG_CREATE,
		nullptr,
		&raw_path);
	if(FAILED(result))
	{
		return std::unexpected(InjectFailure {
			.error = InjectError::injection_state_root_failed,
			.win32_error = static_cast<DWORD>(result),
		});
	}
	const std::filesystem::path root =
		std::filesystem::path(raw_path) /
		L"MinecraftDungeonsModKit" /
		L"injection-state";
	CoTaskMemFree(raw_path);
	return InjectionStateStore(root);
}

/// Returns the versioned marker path for one PID/creation-time identity.
std::filesystem::path InjectionStateStore::marker_path(
	const TargetIdentity& identity) const
{
	return root_ /
		(L"v1-" + std::to_wstring(identity.process_id) + L"-" +
		 std::to_wstring(identity.creation_time) + L".state");
}

/// Returns whether one identity has retained uncertain loader state.
std::expected<bool, InjectFailure> InjectionStateStore::exists(
	const TargetIdentity& identity) const
{
	const DWORD attributes = GetFileAttributesW(marker_path(identity).c_str());
	if(attributes != INVALID_FILE_ATTRIBUTES)
	{
		return true;
	}
	const DWORD error = GetLastError();
	if(error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
	{
		return false;
	}
	return std::unexpected(InjectFailure {
		.error = InjectError::injection_state_query_failed,
		.win32_error = error,
	});
}

/// Atomically creates and durably writes one in-progress identity marker.
std::expected<void, InjectFailure> InjectionStateStore::create(
	const TargetIdentity& identity) const
{
	std::error_code directory_error;
	std::filesystem::create_directories(root_, directory_error);
	if(directory_error)
	{
		return std::unexpected(InjectFailure {
			.error = InjectError::injection_state_root_failed,
			.win32_error = static_cast<DWORD>(directory_error.value()),
		});
	}

	const auto path = marker_path(identity);
	const HANDLE file = CreateFileW(
		path.c_str(),
		GENERIC_WRITE,
		FILE_SHARE_READ,
		nullptr,
		CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
		nullptr);
	if(file == INVALID_HANDLE_VALUE)
	{
		const DWORD error = GetLastError();
		return std::unexpected(InjectFailure {
			.error = error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS
				? InjectError::injection_state_uncertain
				: InjectError::injection_state_create_failed,
			.win32_error = error,
		});
	}

	// Version 1 is UTF-8-compatible ASCII:
	// magic, PID, process creation FILETIME ticks, and fail-closed state.
	const std::string content =
		"MCD_INJECTION_STATE_V1\npid=" + std::to_string(identity.process_id) +
		"\ncreation_time_100ns=" + std::to_string(identity.creation_time) +
		"\nstate=loader_started_or_uncertain\n";
	DWORD written = 0U;
	const BOOL write_succeeded = WriteFile(
		file,
		content.data(),
		static_cast<DWORD>(content.size()),
		&written,
		nullptr);
	DWORD error = write_succeeded ? ERROR_SUCCESS : GetLastError();
	if(write_succeeded && written == content.size() && !FlushFileBuffers(file))
	{
		error = GetLastError();
	}
	const BOOL close_succeeded = CloseHandle(file);
	if(error == ERROR_SUCCESS && !close_succeeded)
	{
		error = GetLastError();
	}
	if(error != ERROR_SUCCESS || written != content.size())
	{
		DeleteFileW(path.c_str());
		return std::unexpected(InjectFailure {
			.error = InjectError::injection_state_write_failed,
			.win32_error = error == ERROR_SUCCESS ? ERROR_WRITE_FAULT : error,
		});
	}
	return {};
}

/// Removes one marker after loader completion is definitive.
std::expected<void, InjectFailure> InjectionStateStore::clear(
	const TargetIdentity& identity) const
{
	if(DeleteFileW(marker_path(identity).c_str()))
	{
		return {};
	}
	const DWORD error = GetLastError();
	if(error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
	{
		return {};
	}
	return std::unexpected(InjectFailure {
		.error = InjectError::injection_state_cleanup_failed,
		.win32_error = error,
	});
}

/// Reconciles persisted state with the currently observed module set.
std::expected<InjectionStateDecision, InjectFailure> evaluate_injection_state(
	const InjectionStateStore& store,
	const TargetIdentity& identity,
	const ModuleMatch module_match)
{
	if(module_match == ModuleMatch::ambiguous)
	{
		return std::unexpected(InjectFailure {
			.error = InjectError::module_ambiguous,
			.win32_error = ERROR_DUP_NAME,
		});
	}
	const auto marker_exists = store.exists(identity);
	if(!marker_exists)
	{
		return std::unexpected(marker_exists.error());
	}
	if(module_match == ModuleMatch::exact)
	{
		if(*marker_exists)
		{
			const auto cleared = store.clear(identity);
			if(!cleared)
			{
				return std::unexpected(cleared.error());
			}
		}
		return InjectionStateDecision::already_loaded;
	}
	if(*marker_exists)
	{
		return std::unexpected(InjectFailure {
			.error = InjectError::injection_state_uncertain,
			.win32_error = ERROR_BUSY,
		});
	}
	return InjectionStateDecision::proceed;
}
}

namespace mcd::launcher
{
/// Records ownership of one successfully acquired mutex.
TargetInjectionLock::TargetInjectionLock(const HANDLE mutex) noexcept
	: mutex_(mutex)
{
}

/// Releases the mutex when owned and closes its kernel handle.
TargetInjectionLock::~TargetInjectionLock() noexcept
{
	if(mutex_)
	{
		ReleaseMutex(mutex_);
		CloseHandle(mutex_);
	}
}

/// Transfers one mutex acquisition.
TargetInjectionLock::TargetInjectionLock(TargetInjectionLock&& other) noexcept
	: mutex_(std::exchange(other.mutex_, nullptr))
{
}

/// Replaces this lock with a transferred mutex acquisition.
TargetInjectionLock& TargetInjectionLock::operator=(TargetInjectionLock&& other) noexcept
{
	if(this != &other)
	{
		if(mutex_)
		{
			ReleaseMutex(mutex_);
			CloseHandle(mutex_);
		}
		mutex_ = std::exchange(other.mutex_, nullptr);
	}
	return *this;
}

/// Acquires the target/build mutex before a bounded deadline.
std::expected<TargetInjectionLock, InjectFailure> TargetInjectionLock::acquire(
	const DWORD process_id,
	const std::wstring_view build_id,
	const DWORD timeout_ms)
{
	std::wstring safe_build;
	safe_build.reserve(build_id.size());
	for(const wchar_t character : build_id)
	{
		const bool allowed =
			(character >= L'a' && character <= L'z') ||
			(character >= L'A' && character <= L'Z') ||
			(character >= L'0' && character <= L'9') ||
			character == L'-' ||
			character == L'_';
		safe_build.push_back(allowed ? character : L'_');
	}
	const std::wstring name =
		L"Local\\mcd-inject-" + std::to_wstring(process_id) + L"-" + safe_build;
	const HANDLE mutex = CreateMutexW(nullptr, FALSE, name.c_str());
	if(!mutex)
	{
		return std::unexpected(InjectFailure {
			.error = InjectError::synchronization_failed,
			.win32_error = GetLastError(),
		});
	}

	const DWORD wait_result = WaitForSingleObject(mutex, timeout_ms);
	if(wait_result == WAIT_OBJECT_0 || wait_result == WAIT_ABANDONED)
	{
		return TargetInjectionLock(mutex);
	}
	const DWORD error = wait_result == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
	CloseHandle(mutex);
	return std::unexpected(InjectFailure {
		.error = wait_result == WAIT_TIMEOUT
			? InjectError::synchronization_timeout
			: InjectError::synchronization_failed,
		.win32_error = error,
	});
}

/// Validates and canonicalizes an absolute existing runtime DLL path.
std::expected<std::filesystem::path, InjectError> validate_runtime_path(
	const std::filesystem::path& runtime_path)
{
	if(!runtime_path.is_absolute())
	{
		return std::unexpected(InjectError::runtime_path_not_absolute);
	}

	std::error_code status_error;
	const auto status = std::filesystem::status(runtime_path, status_error);
	if(status_error || !std::filesystem::exists(status))
	{
		return std::unexpected(InjectError::runtime_not_found);
	}
	if(!std::filesystem::is_regular_file(status))
	{
		return std::unexpected(InjectError::runtime_not_regular_file);
	}

	std::error_code canonical_error;
	const auto canonical = std::filesystem::canonical(runtime_path, canonical_error);
	if(canonical_error)
	{
		return std::unexpected(InjectError::runtime_path_resolution_failed);
	}
	return canonical;
}

/// Verifies that a process image is the same canonical path inspected by the caller.
std::expected<void, InjectError> validate_process_image(
	const std::filesystem::path& inspected_path,
	const std::filesystem::path& process_path)
{
	if(!equal_windows_path(inspected_path, process_path))
	{
		return std::unexpected(InjectError::process_image_mismatch);
	}
	return {};
}

/// Returns whether launcher and target effective machine types match.
bool architectures_compatible(
	const USHORT launcher_process_machine,
	const USHORT launcher_native_machine,
	const USHORT target_process_machine,
	const USHORT target_native_machine) noexcept
{
	if(launcher_native_machine == IMAGE_FILE_MACHINE_UNKNOWN ||
	   target_native_machine == IMAGE_FILE_MACHINE_UNKNOWN ||
	   launcher_native_machine != target_native_machine)
	{
		return false;
	}
	const USHORT launcher_effective =
		launcher_process_machine == IMAGE_FILE_MACHINE_UNKNOWN
		? launcher_native_machine
		: launcher_process_machine;
	const USHORT target_effective =
		target_process_machine == IMAGE_FILE_MACHINE_UNKNOWN
		? target_native_machine
		: target_process_machine;
	return launcher_effective == target_effective;
}

/// Classifies one canonical module path without forgetting prior matches.
ModuleMatch classify_runtime_module(
	const std::filesystem::path& runtime_path,
	const std::filesystem::path& module_path) noexcept
{
	if(_wcsicmp(runtime_path.filename().c_str(), module_path.filename().c_str()) != 0)
	{
		return ModuleMatch::none;
	}
	return equal_windows_path(runtime_path, module_path)
		? ModuleMatch::exact
		: ModuleMatch::ambiguous;
}

/// Merges one module observation with ambiguity taking precedence.
ModuleMatch merge_module_match(
	const ModuleMatch current,
	const ModuleMatch observed) noexcept
{
	if(current == ModuleMatch::ambiguous || observed == ModuleMatch::ambiguous)
	{
		return ModuleMatch::ambiguous;
	}
	if(current == ModuleMatch::exact || observed == ModuleMatch::exact)
	{
		return ModuleMatch::exact;
	}
	return ModuleMatch::none;
}

/// Derives a remote export address from local and remote module bases.
std::expected<std::uintptr_t, InjectError> remote_export_address(
	const std::uintptr_t local_module,
	const std::size_t local_module_size,
	const std::uintptr_t local_export,
	const std::uintptr_t remote_module) noexcept
{
	if(local_export < local_module || local_module_size == 0U)
	{
		return std::unexpected(InjectError::invalid_loader_address);
	}
	const std::uintptr_t offset = local_export - local_module;
	if(offset >= local_module_size)
	{
		return std::unexpected(InjectError::invalid_loader_address);
	}
	if(remote_module > std::numeric_limits<std::uintptr_t>::max() - offset)
	{
		return std::unexpected(InjectError::invalid_loader_address);
	}
	return remote_module + offset;
}

/// Loads one validated absolute runtime DLL into the exact selected process.
std::expected<InjectionResult, InjectFailure> inject_runtime(
	const ProcessInfo& process,
	const std::filesystem::path& inspected_path,
	const std::wstring_view build_id,
	const std::filesystem::path& runtime_path)
{
	const auto validated_runtime = validate_runtime_path(runtime_path);
	if(!validated_runtime)
	{
		return std::unexpected(InjectFailure {
			.error = validated_runtime.error(),
			.win32_error = ERROR_INVALID_PARAMETER,
		});
	}
	UniqueHandle target(OpenProcess(injection_access, FALSE, process.id));
	if(!target.valid())
	{
		return std::unexpected(InjectFailure {
			.error = InjectError::process_open_failed,
			.win32_error = GetLastError(),
		});
	}

	const auto target_path = held_process_image_path(target.get());
	if(!target_path)
	{
		return std::unexpected(target_path.error());
	}
	const auto validated_process =
		validate_process_image(inspected_path, *target_path);
	if(!validated_process)
	{
		return std::unexpected(InjectFailure {
			.error = validated_process.error(),
			.win32_error = ERROR_INVALID_NAME,
		});
	}

	const auto architecture = validate_architecture(target.get());
	if(!architecture)
	{
		return std::unexpected(architecture.error());
	}

	auto injection_lock = TargetInjectionLock::acquire(
		GetProcessId(target.get()),
		build_id,
		synchronization_timeout_ms);
	if(!injection_lock)
	{
		return std::unexpected(injection_lock.error());
	}

	const auto identity = target_identity(target.get());
	if(!identity)
	{
		return std::unexpected(identity.error());
	}

	const auto modules = inspect_modules(target.get(), *validated_runtime);
	if(!modules)
	{
		return std::unexpected(modules.error());
	}
	const auto state_store = detail::InjectionStateStore::current_user();
	if(!state_store)
	{
		return std::unexpected(state_store.error());
	}
	const auto state = detail::evaluate_injection_state(
		*state_store,
		*identity,
		modules->first);
	if(!state)
	{
		return std::unexpected(state.error());
	}
	if(*state == detail::InjectionStateDecision::already_loaded)
	{
		return InjectionResult::already_loaded;
	}

	const HMODULE local_kernel32 = GetModuleHandleW(L"kernel32.dll");
	const FARPROC local_load_library = local_kernel32
		? GetProcAddress(local_kernel32, "LoadLibraryW")
		: nullptr;
	if(!local_kernel32 || !local_load_library)
	{
		return std::unexpected(InjectFailure {
			.error = InjectError::loader_resolution_failed,
			.win32_error = GetLastError(),
		});
	}
	const auto local_kernel32_size = module_image_size(local_kernel32);
	if(!local_kernel32_size)
	{
		return std::unexpected(InjectFailure {
			.error = InjectError::loader_resolution_failed,
			.win32_error = local_kernel32_size.error(),
		});
	}
	const auto remote_loader = remote_export_address(
		reinterpret_cast<std::uintptr_t>(local_kernel32),
		*local_kernel32_size,
		reinterpret_cast<std::uintptr_t>(local_load_library),
		modules->second);
	if(!remote_loader)
	{
		return std::unexpected(InjectFailure {
			.error = remote_loader.error(),
			.win32_error = ERROR_INVALID_ADDRESS,
		});
	}

	const std::wstring runtime_text = validated_runtime->native();
	const SIZE_T byte_count = (runtime_text.size() + 1U) * sizeof(wchar_t);
	RemoteAllocation remote_path(
		target.get(),
		VirtualAllocEx(
			target.get(),
			nullptr,
			byte_count,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE));
	if(!remote_path.get())
	{
		return std::unexpected(InjectFailure {
			.error = InjectError::remote_allocation_failed,
			.win32_error = GetLastError(),
		});
	}
	const auto release_before_failure =
		[&remote_path](const InjectFailure failure) noexcept {
			const DWORD release_error = remote_path.release();
			if(release_error != ERROR_SUCCESS)
			{
				return InjectFailure {
					.error = InjectError::remote_memory_release_failed,
					.win32_error = release_error,
				};
			}
			return failure;
		};

	SIZE_T written = 0U;
	if(!WriteProcessMemory(
		   target.get(),
		   remote_path.get(),
		   runtime_text.c_str(),
		   byte_count,
		   &written) ||
	   written != byte_count)
	{
		const DWORD error = GetLastError();
		return std::unexpected(release_before_failure(InjectFailure {
			.error = InjectError::remote_write_failed,
			.win32_error = error == ERROR_SUCCESS ? ERROR_WRITE_FAULT : error,
		}));
	}

	const auto marker_created = state_store->create(*identity);
	if(!marker_created)
	{
		return std::unexpected(release_before_failure(marker_created.error()));
	}
	const auto definitive_failure =
		[&remote_path, &state_store, &identity](
			const InjectFailure failure) noexcept {
			const DWORD release_error = remote_path.release();
			const auto marker_cleared = state_store->clear(*identity);
			if(!marker_cleared)
			{
				return marker_cleared.error();
			}
			if(release_error != ERROR_SUCCESS)
			{
				return InjectFailure {
					.error = InjectError::remote_memory_release_failed,
					.win32_error = release_error,
				};
			}
			return failure;
		};

	const auto thread_entry =
		reinterpret_cast<LPTHREAD_START_ROUTINE>(*remote_loader);
	UniqueHandle thread(CreateRemoteThread(
		target.get(),
		nullptr,
		0U,
		thread_entry,
		remote_path.get(),
		0U,
		nullptr));
	if(!thread.valid())
	{
		return std::unexpected(definitive_failure(InjectFailure {
			.error = InjectError::remote_thread_failed,
			.win32_error = GetLastError(),
		}));
	}

	const DWORD wait_result = WaitForSingleObject(thread.get(), injection_timeout_ms);
	if(wait_result == WAIT_TIMEOUT)
	{
		// The pending thread may still read this allocation. Leaking these few
		// bytes is safer than creating a cross-process use-after-free.
		remote_path.abandon();
		return std::unexpected(InjectFailure {
			.error = InjectError::remote_thread_timeout,
			.win32_error = ERROR_TIMEOUT,
		});
	}
	if(wait_result != WAIT_OBJECT_0)
	{
		const DWORD error = wait_result == WAIT_FAILED ? GetLastError() : ERROR_GEN_FAILURE;
		remote_path.abandon();
		return std::unexpected(InjectFailure {
			.error = InjectError::remote_thread_wait_failed,
			.win32_error = error,
		});
	}

	DWORD load_result = 0U;
	if(!GetExitCodeThread(thread.get(), &load_result))
	{
		return std::unexpected(definitive_failure(InjectFailure {
			.error = InjectError::remote_thread_wait_failed,
			.win32_error = GetLastError(),
		}));
	}
	if(load_result == 0U)
	{
		return std::unexpected(definitive_failure(InjectFailure {
			.error = InjectError::remote_load_failed,
			.win32_error = ERROR_DLL_INIT_FAILED,
		}));
	}

	const DWORD release_error = remote_path.release();
	const auto marker_cleared = state_store->clear(*identity);
	if(!marker_cleared)
	{
		return std::unexpected(marker_cleared.error());
	}
	if(release_error != ERROR_SUCCESS)
	{
		return std::unexpected(InjectFailure {
			.error = InjectError::remote_memory_release_failed,
			.win32_error = release_error,
		});
	}
	return InjectionResult::injected;
}

/// Returns a stable diagnostic name for one injection error.
std::string inject_error_message(const InjectFailure& failure)
{
	switch(failure.error)
	{
	case InjectError::runtime_path_not_absolute:
		return "runtime DLL path is not absolute";
	case InjectError::runtime_not_found:
		return "runtime DLL does not exist";
	case InjectError::runtime_not_regular_file:
		return "runtime DLL path is not a regular file";
	case InjectError::runtime_path_resolution_failed:
		return "runtime DLL path could not be canonicalized";
	case InjectError::process_image_mismatch:
		return "running process image differs from inspected executable";
	case InjectError::process_open_failed:
		return "opening target process failed";
	case InjectError::process_time_query_failed:
		return "target process creation time query failed";
	case InjectError::architecture_query_failed:
		return "target architecture query failed";
	case InjectError::architecture_mismatch:
		return "launcher and target architectures differ";
	case InjectError::synchronization_failed:
		return "target injection synchronization failed";
	case InjectError::synchronization_timeout:
		return "target injection synchronization timed out";
	case InjectError::module_snapshot_failed:
		return "target module snapshot failed";
	case InjectError::module_query_failed:
		return "target module enumeration failed";
	case InjectError::module_ambiguous:
		return "same-named runtime module has a different path";
	case InjectError::injection_state_root_failed:
		return "injection state directory resolution failed";
	case InjectError::injection_state_query_failed:
		return "injection state marker query failed";
	case InjectError::injection_state_create_failed:
		return "injection state marker creation failed";
	case InjectError::injection_state_write_failed:
		return "injection state marker write failed";
	case InjectError::injection_state_cleanup_failed:
		return "injection state marker cleanup failed";
	case InjectError::injection_state_uncertain:
		return "prior injection outcome remains uncertain";
	case InjectError::loader_resolution_failed:
		return "LoadLibraryW resolution failed";
	case InjectError::invalid_loader_address:
		return "remote LoadLibraryW address was invalid";
	case InjectError::remote_allocation_failed:
		return "remote path allocation failed";
	case InjectError::remote_write_failed:
		return "remote path write failed";
	case InjectError::remote_thread_failed:
		return "remote loader thread creation failed";
	case InjectError::remote_thread_timeout:
		return "remote loader thread timed out";
	case InjectError::remote_thread_wait_failed:
		return "remote loader thread wait failed";
	case InjectError::remote_load_failed:
		return "LoadLibraryW rejected the runtime DLL";
	case InjectError::remote_memory_release_failed:
		return "remote path memory release failed";
	}
	return "unknown injection error";
}
}
