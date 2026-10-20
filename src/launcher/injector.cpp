#include "mcd/launcher/injector.hpp"

#include <limits>
#include <utility>

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
std::expected<std::pair<bool, std::uintptr_t>, mcd::launcher::InjectFailure> inspect_modules(
	const DWORD process_id,
	const std::filesystem::path& runtime_path)
{
	auto snapshot = module_snapshot(process_id);
	if(!snapshot)
	{
		return std::unexpected(mcd::launcher::InjectFailure {
			.error = mcd::launcher::InjectError::module_snapshot_failed,
			.win32_error = snapshot.error(),
		});
	}

	bool runtime_loaded = false;
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
			runtime_loaded = equal_windows_path(module_path, runtime_path);
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
	return std::pair {runtime_loaded, kernel32_base};
}
}

namespace mcd::launcher
{
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
	const auto validated_process =
		validate_process_image(inspected_path, process.image_path);
	if(!validated_process)
	{
		return std::unexpected(InjectFailure {
			.error = validated_process.error(),
			.win32_error = ERROR_INVALID_NAME,
		});
	}

	const auto modules = inspect_modules(process.id, *validated_runtime);
	if(!modules)
	{
		return std::unexpected(modules.error());
	}
	if(modules->first)
	{
		return InjectionResult::already_loaded;
	}

	UniqueHandle target(OpenProcess(injection_access, FALSE, process.id));
	if(!target.valid())
	{
		return std::unexpected(InjectFailure {
			.error = InjectError::process_open_failed,
			.win32_error = GetLastError(),
		});
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
		return std::unexpected(release_before_failure(InjectFailure {
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
		return std::unexpected(release_before_failure(InjectFailure {
			.error = InjectError::remote_thread_wait_failed,
			.win32_error = GetLastError(),
		}));
	}
	if(load_result == 0U)
	{
		return std::unexpected(release_before_failure(InjectFailure {
			.error = InjectError::remote_load_failed,
			.win32_error = ERROR_DLL_INIT_FAILED,
		}));
	}

	const DWORD release_error = remote_path.release();
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
	case InjectError::module_snapshot_failed:
		return "target module snapshot failed";
	case InjectError::module_query_failed:
		return "target module enumeration failed";
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
