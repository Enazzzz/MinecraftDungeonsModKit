#include "mcd/launcher/process.hpp"

#include <cwchar>
#include <limits>
#include <system_error>
#include <utility>
#include <vector>

#include <tlhelp32.h>

namespace
{
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

/// Compares canonical Windows paths using ordinal case-insensitive semantics.
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
}

namespace mcd::launcher
{
/// Returns the canonical image path of one process opened for limited query access.
std::expected<std::filesystem::path, ProcessFailure> process_image_path(
	const DWORD process_id)
{
	UniqueHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id));
	if(!process.valid())
	{
		return std::unexpected(ProcessFailure {
			.error = ProcessError::query_failed,
			.win32_error = GetLastError(),
		});
	}

	std::vector<wchar_t> buffer(32'768U);
	DWORD length = static_cast<DWORD>(buffer.size());
	if(!QueryFullProcessImageNameW(process.get(), 0U, buffer.data(), &length))
	{
		return std::unexpected(ProcessFailure {
			.error = ProcessError::query_failed,
			.win32_error = GetLastError(),
		});
	}

	std::error_code error;
	const auto canonical = std::filesystem::canonical(
		std::filesystem::path(std::wstring_view(buffer.data(), length)),
		error);
	if(error)
	{
		return std::unexpected(ProcessFailure {
			.error = ProcessError::query_failed,
			.win32_error = static_cast<DWORD>(error.value()),
		});
	}
	return canonical;
}

/// Locates exactly one process whose canonical image is the requested executable.
std::expected<ProcessInfo, ProcessFailure> find_process(
	const std::filesystem::path& executable_path)
{
	std::error_code canonical_error;
	const auto canonical_executable =
		std::filesystem::canonical(executable_path, canonical_error);
	if(canonical_error)
	{
		return std::unexpected(ProcessFailure {
			.error = ProcessError::query_failed,
			.win32_error = static_cast<DWORD>(canonical_error.value()),
		});
	}

	UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0U));
	if(!snapshot.valid())
	{
		return std::unexpected(ProcessFailure {
			.error = ProcessError::snapshot_failed,
			.win32_error = GetLastError(),
		});
	}

	PROCESSENTRY32W entry {.dwSize = sizeof(PROCESSENTRY32W)};
	if(!Process32FirstW(snapshot.get(), &entry))
	{
		return std::unexpected(ProcessFailure {
			.error = ProcessError::snapshot_failed,
			.win32_error = GetLastError(),
		});
	}

	std::vector<ProcessInfo> matches;
	do
	{
		if(_wcsicmp(entry.szExeFile, canonical_executable.filename().c_str()) != 0)
		{
			continue;
		}

		const auto image = process_image_path(entry.th32ProcessID);
		if(!image)
		{
			return std::unexpected(image.error());
		}
		if(equal_windows_path(*image, canonical_executable))
		{
			matches.push_back({
				.id = entry.th32ProcessID,
			});
		}
	}
	while(Process32NextW(snapshot.get(), &entry));

	const DWORD enumeration_error = GetLastError();
	if(enumeration_error != ERROR_NO_MORE_FILES)
	{
		return std::unexpected(ProcessFailure {
			.error = ProcessError::snapshot_failed,
			.win32_error = enumeration_error,
		});
	}
	if(matches.empty())
	{
		return std::unexpected(ProcessFailure {
			.error = ProcessError::not_found,
			.win32_error = ERROR_NOT_FOUND,
		});
	}
	if(matches.size() != 1U)
	{
		return std::unexpected(ProcessFailure {
			.error = ProcessError::multiple_matches,
			.win32_error = ERROR_MORE_DATA,
		});
	}
	return matches.front();
}

/// Parses one nonzero process ID from strict ASCII decimal text.
std::optional<DWORD> parse_process_id(const std::wstring_view text) noexcept
{
	if(text.empty())
	{
		return std::nullopt;
	}

	std::uint64_t value = 0U;
	for(const wchar_t character : text)
	{
		if(character < L'0' || character > L'9')
		{
			return std::nullopt;
		}
		const unsigned int digit = static_cast<unsigned int>(character - L'0');
		if(value > (std::numeric_limits<DWORD>::max() - digit) / 10U)
		{
			return std::nullopt;
		}
		value = (value * 10U) + digit;
	}
	if(value == 0U)
	{
		return std::nullopt;
	}
	return static_cast<DWORD>(value);
}

/// Returns a stable diagnostic name for one process-discovery error.
std::string process_error_message(const ProcessFailure& failure)
{
	switch(failure.error)
	{
	case ProcessError::snapshot_failed:
		return "process snapshot failed";
	case ProcessError::query_failed:
		return "process image query failed";
	case ProcessError::not_found:
		return "matching game process not found";
	case ProcessError::multiple_matches:
		return "multiple matching game processes found";
	}
	return "unknown process error";
}
}
