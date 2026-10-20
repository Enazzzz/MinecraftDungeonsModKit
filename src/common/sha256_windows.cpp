#include "mcd/sha256.hpp"

#include <array>
#include <utility>
#include <vector>

#include <windows.h>
#include <bcrypt.h>
#include <winternl.h>

namespace
{
/// Converts the current thread's last Win32 error into a standard error code.
std::error_code last_error_code()
{
	return std::error_code(
		static_cast<int>(GetLastError()),
		std::system_category());
}

/// Translates an NTSTATUS value into a Win32-backed standard error code.
std::error_code ntstatus_error(const NTSTATUS status)
{
	ULONG translated = RtlNtStatusToDosError(status);
	if(translated == ERROR_MR_MID_NOT_FOUND)
	{
		translated = static_cast<ULONG>(status);
	}

	return std::error_code(
		static_cast<int>(translated),
		std::system_category());
}

/// Owns a BCrypt algorithm provider handle.
class AlgorithmHandle
{
public:
	/// Opens the SHA-256 BCrypt algorithm provider.
	static std::expected<AlgorithmHandle, std::error_code> open_sha256()
	{
		BCRYPT_ALG_HANDLE handle = nullptr;
		const NTSTATUS status =
			BCryptOpenAlgorithmProvider(&handle, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
		if(!BCRYPT_SUCCESS(status))
		{
			return std::unexpected(ntstatus_error(status));
		}

		return AlgorithmHandle(handle);
	}

	AlgorithmHandle(const AlgorithmHandle&) = delete;
	AlgorithmHandle& operator=(const AlgorithmHandle&) = delete;

	/// Transfers ownership from another algorithm handle wrapper.
	AlgorithmHandle(AlgorithmHandle&& other) noexcept : handle_(other.handle_)
	{
		other.handle_ = nullptr;
	}

	/// Transfers ownership through move assignment.
	AlgorithmHandle& operator=(AlgorithmHandle&& other) noexcept
	{
		if(this != &other)
		{
			close();
			handle_ = other.handle_;
			other.handle_ = nullptr;
		}

		return *this;
	}

	/// Closes the BCrypt algorithm provider.
	~AlgorithmHandle()
	{
		close();
	}

	/// Returns the native BCrypt handle.
	[[nodiscard]] BCRYPT_ALG_HANDLE get() const
	{
		return handle_;
	}

	/// Reads a DWORD property from the algorithm provider.
	[[nodiscard]] std::expected<DWORD, std::error_code> get_dword_property(
		const wchar_t* property_name) const
	{
		DWORD value = 0;
		DWORD bytes_written = 0;
		const NTSTATUS status = BCryptGetProperty(
			handle_,
			property_name,
			reinterpret_cast<PUCHAR>(&value),
			sizeof(value),
			&bytes_written,
			0);
		if(!BCRYPT_SUCCESS(status))
		{
			return std::unexpected(ntstatus_error(status));
		}

		return value;
	}

private:
	/// Stores an already opened algorithm provider.
	explicit AlgorithmHandle(BCRYPT_ALG_HANDLE handle) : handle_(handle)
	{
	}

	/// Releases the owned BCrypt algorithm provider.
	void close()
	{
		if(handle_ != nullptr)
		{
			(void)BCryptCloseAlgorithmProvider(handle_, 0);
			handle_ = nullptr;
		}
	}

	BCRYPT_ALG_HANDLE handle_ = nullptr;
};

/// Owns a BCrypt hash handle and its required backing object buffer.
class HashHandle
{
public:
	/// Creates a SHA-256 hash object from the supplied algorithm provider.
	static std::expected<HashHandle, std::error_code> create(
		const AlgorithmHandle& algorithm)
	{
		const auto object_length = algorithm.get_dword_property(BCRYPT_OBJECT_LENGTH);
		if(!object_length.has_value())
		{
			return std::unexpected(object_length.error());
		}

		HashHandle wrapper;
		wrapper.object_buffer_.resize(*object_length);

		const NTSTATUS status = BCryptCreateHash(
			algorithm.get(),
			&wrapper.handle_,
			wrapper.object_buffer_.data(),
			static_cast<ULONG>(wrapper.object_buffer_.size()),
			nullptr,
			0,
			0);
		if(!BCRYPT_SUCCESS(status))
		{
			return std::unexpected(ntstatus_error(status));
		}

		return std::move(wrapper);
	}

	HashHandle(const HashHandle&) = delete;
	HashHandle& operator=(const HashHandle&) = delete;

	/// Transfers ownership from another hash wrapper.
	HashHandle(HashHandle&& other) noexcept
		: handle_(other.handle_),
		  object_buffer_(std::move(other.object_buffer_))
	{
		other.handle_ = nullptr;
	}

	/// Transfers ownership through move assignment.
	HashHandle& operator=(HashHandle&& other) noexcept
	{
		if(this != &other)
		{
			close();
			handle_ = other.handle_;
			object_buffer_ = std::move(other.object_buffer_);
			other.handle_ = nullptr;
		}

		return *this;
	}

	/// Destroys the BCrypt hash object.
	~HashHandle()
	{
		close();
	}

	/// Adds a contiguous block of file data into the running hash.
	[[nodiscard]] std::error_code hash_data(const std::byte* data, const ULONG size)
	{
		const NTSTATUS status = BCryptHashData(
			handle_,
			reinterpret_cast<PUCHAR>(const_cast<std::byte*>(data)),
			size,
			0);
		if(!BCRYPT_SUCCESS(status))
		{
			return ntstatus_error(status);
		}

		return {};
	}

	/// Finalizes the hash and returns the SHA-256 digest bytes.
	[[nodiscard]] std::expected<mcd::Sha256Digest, std::error_code> finish()
	{
		mcd::Sha256Digest digest {};
		const NTSTATUS status = BCryptFinishHash(
			handle_,
			reinterpret_cast<PUCHAR>(digest.data()),
			static_cast<ULONG>(digest.size()),
			0);
		if(!BCRYPT_SUCCESS(status))
		{
			return std::unexpected(ntstatus_error(status));
		}

		return digest;
	}

private:
	/// Creates an empty wrapper before a BCrypt hash handle is attached.
	HashHandle() = default;

	/// Releases the owned BCrypt hash handle.
	void close()
	{
		if(handle_ != nullptr)
		{
			(void)BCryptDestroyHash(handle_);
			handle_ = nullptr;
		}
	}

	BCRYPT_HASH_HANDLE handle_ = nullptr;
	std::vector<UCHAR> object_buffer_;
};

/// Owns a Win32 file handle.
class FileHandle
{
public:
	/// Opens a file for buffered read-only hashing.
	static std::expected<FileHandle, std::error_code> open(
		const std::filesystem::path& path)
	{
		const HANDLE handle = CreateFileW(
			path.c_str(),
			GENERIC_READ,
			FILE_SHARE_READ,
			nullptr,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
			nullptr);
		if(handle == INVALID_HANDLE_VALUE)
		{
			return std::unexpected(last_error_code());
		}

		return FileHandle(handle);
	}

	FileHandle(const FileHandle&) = delete;
	FileHandle& operator=(const FileHandle&) = delete;

	/// Transfers ownership from another file wrapper.
	FileHandle(FileHandle&& other) noexcept : handle_(other.handle_)
	{
		other.handle_ = INVALID_HANDLE_VALUE;
	}

	/// Transfers ownership through move assignment.
	FileHandle& operator=(FileHandle&& other) noexcept
	{
		if(this != &other)
		{
			close();
			handle_ = other.handle_;
			other.handle_ = INVALID_HANDLE_VALUE;
		}

		return *this;
	}

	/// Closes the underlying file handle.
	~FileHandle()
	{
		close();
	}

	/// Returns the native Win32 handle.
	[[nodiscard]] HANDLE get() const
	{
		return handle_;
	}

private:
	/// Stores an already opened file handle.
	explicit FileHandle(HANDLE handle) : handle_(handle)
	{
	}

	/// Releases the owned file handle.
	void close()
	{
		if(handle_ != INVALID_HANDLE_VALUE)
		{
			(void)CloseHandle(handle_);
			handle_ = INVALID_HANDLE_VALUE;
		}
	}

	HANDLE handle_ = INVALID_HANDLE_VALUE;
};
}

namespace mcd
{
/// Hashes a file through the Windows BCrypt SHA-256 provider.
std::expected<Sha256Digest, std::error_code> sha256_file(
	const std::filesystem::path& path)
{
	const auto algorithm = AlgorithmHandle::open_sha256();
	if(!algorithm.has_value())
	{
		return std::unexpected(algorithm.error());
	}

	const auto hash_length = algorithm->get_dword_property(BCRYPT_HASH_LENGTH);
	if(!hash_length.has_value())
	{
		return std::unexpected(hash_length.error());
	}

	if(*hash_length != Sha256Digest {}.size())
	{
		return std::unexpected(
			std::error_code(static_cast<int>(ERROR_INVALID_DATA), std::system_category()));
	}

	auto hash = HashHandle::create(*algorithm);
	if(!hash.has_value())
	{
		return std::unexpected(hash.error());
	}

	const auto file = FileHandle::open(path);
	if(!file.has_value())
	{
		return std::unexpected(file.error());
	}

	constexpr DWORD chunk_size = 1024U * 1024U;
	std::vector<std::byte> buffer(chunk_size);
	auto hash_wrapper = std::move(*hash);

	for(;;)
	{
		DWORD bytes_read = 0;
		if(!ReadFile(file->get(), buffer.data(), chunk_size, &bytes_read, nullptr))
		{
			return std::unexpected(last_error_code());
		}

		if(bytes_read == 0)
		{
			break;
		}

		if(const std::error_code error =
			   hash_wrapper.hash_data(buffer.data(), bytes_read);
		   error)
		{
			return std::unexpected(error);
		}
	}

	return hash_wrapper.finish();
}
}
