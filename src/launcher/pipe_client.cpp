#include "mcd/launcher/pipe_client.hpp"

#include <chrono>
#include <cstddef>
#include <limits>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include "mcd/protocol.hpp"
#include "mcd/wire.hpp"

namespace
{
constexpr DWORD pipe_timeout_ms = 5'000U;
constexpr DWORD cancellation_timeout_ms = 500U;

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

/// Owns storage referenced by one asynchronous pipe operation.
struct PipeOperation
{
	OVERLAPPED overlapped {};
	UniqueHandle event;
	std::vector<std::byte> buffer;
};

/// Returns the remaining bounded operation time in milliseconds.
DWORD remaining_time(const std::chrono::steady_clock::time_point deadline) noexcept
{
	const auto now = std::chrono::steady_clock::now();
	if(now >= deadline)
	{
		return 0U;
	}
	const auto remaining =
		std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
	return static_cast<DWORD>(
		remaining > std::numeric_limits<DWORD>::max()
		? std::numeric_limits<DWORD>::max()
		: remaining);
}

/// Retains operation storage if cancellation cannot be confirmed promptly.
void cancel_operation(
	const HANDLE pipe,
	std::unique_ptr<PipeOperation>& operation) noexcept
{
	CancelIoEx(pipe, &operation->overlapped);
	const DWORD wait_result =
		WaitForSingleObject(operation->event.get(), cancellation_timeout_ms);
	if(wait_result != WAIT_OBJECT_0)
	{
		(void)operation.release();
	}
}

/// Transfers one exact byte span before the shared deadline.
std::expected<void, mcd::launcher::PipeClientFailure> transfer_exact(
	const HANDLE pipe,
	const std::span<std::byte> bytes,
	const bool writing,
	const std::chrono::steady_clock::time_point deadline)
{
	std::size_t offset = 0U;
	while(offset < bytes.size())
	{
		auto operation = std::make_unique<PipeOperation>();
		operation->event = UniqueHandle(CreateEventW(nullptr, TRUE, FALSE, nullptr));
		if(!operation->event.valid())
		{
			return std::unexpected(mcd::launcher::PipeClientFailure {
				.error = mcd::launcher::PipeClientError::request_failed,
				.win32_error = GetLastError(),
			});
		}
		operation->overlapped.hEvent = operation->event.get();
		operation->buffer.resize(bytes.size() - offset);
		if(writing)
		{
			std::copy(
				bytes.begin() + static_cast<std::ptrdiff_t>(offset),
				bytes.end(),
				operation->buffer.begin());
		}

		DWORD transferred = 0U;
		const BOOL started = writing
			? WriteFile(
				pipe,
				operation->buffer.data(),
				static_cast<DWORD>(operation->buffer.size()),
				nullptr,
				&operation->overlapped)
			: ReadFile(
				pipe,
				operation->buffer.data(),
				static_cast<DWORD>(operation->buffer.size()),
				nullptr,
				&operation->overlapped);
		if(!started && GetLastError() != ERROR_IO_PENDING)
		{
			return std::unexpected(mcd::launcher::PipeClientFailure {
				.error = writing
					? mcd::launcher::PipeClientError::request_failed
					: mcd::launcher::PipeClientError::response_failed,
				.win32_error = GetLastError(),
			});
		}

		const DWORD wait_result =
			WaitForSingleObject(operation->event.get(), remaining_time(deadline));
		if(wait_result == WAIT_TIMEOUT)
		{
			cancel_operation(pipe, operation);
			return std::unexpected(mcd::launcher::PipeClientFailure {
				.error = mcd::launcher::PipeClientError::timeout,
				.win32_error = ERROR_TIMEOUT,
			});
		}
		if(wait_result != WAIT_OBJECT_0)
		{
			const DWORD error = wait_result == WAIT_FAILED ? GetLastError() : ERROR_GEN_FAILURE;
			cancel_operation(pipe, operation);
			return std::unexpected(mcd::launcher::PipeClientFailure {
				.error = writing
					? mcd::launcher::PipeClientError::request_failed
					: mcd::launcher::PipeClientError::response_failed,
				.win32_error = error,
			});
		}
		if(!GetOverlappedResult(
			   pipe,
			   &operation->overlapped,
			   &transferred,
			   FALSE))
		{
			return std::unexpected(mcd::launcher::PipeClientFailure {
				.error = writing
					? mcd::launcher::PipeClientError::request_failed
					: mcd::launcher::PipeClientError::response_failed,
				.win32_error = GetLastError(),
			});
		}
		if(transferred == 0U || transferred > operation->buffer.size())
		{
			return std::unexpected(mcd::launcher::PipeClientFailure {
				.error = mcd::launcher::PipeClientError::response_failed,
				.win32_error = ERROR_BROKEN_PIPE,
			});
		}
		if(!writing)
		{
			std::copy_n(
				operation->buffer.begin(),
				transferred,
				bytes.begin() + static_cast<std::ptrdiff_t>(offset));
		}
		offset += transferred;
	}
	return {};
}
}

namespace mcd::launcher
{
namespace detail
{
/// Returns whether a connected pipe server is the exact requested process.
bool server_process_matches(
	const DWORD requested_process_id,
	const DWORD server_process_id) noexcept
{
	return requested_process_id != 0U &&
		server_process_id == requested_process_id;
}

/// Queries one runtime pipe with a caller-supplied bounded timeout.
std::expected<std::string, PipeClientFailure> query_status(
	const DWORD process_id,
	const DWORD timeout_ms,
	const protocol::MessageKind request_kind,
	const protocol::MessageKind response_kind)
{
	if(process_id == 0U || timeout_ms == 0U)
	{
		return std::unexpected(PipeClientFailure {
			.error = PipeClientError::invalid_process_id,
			.win32_error = ERROR_INVALID_PARAMETER,
		});
	}

	const std::wstring pipe_name =
		L"\\\\.\\pipe\\mcd-runtime-" + std::to_wstring(process_id);
	if(!WaitNamedPipeW(pipe_name.c_str(), timeout_ms))
	{
		const DWORD error = GetLastError();
		return std::unexpected(PipeClientFailure {
			.error = error == ERROR_SEM_TIMEOUT
				? PipeClientError::timeout
				: PipeClientError::open_failed,
			.win32_error = error,
		});
	}

	UniqueHandle pipe(CreateFileW(
		pipe_name.c_str(),
		GENERIC_READ | GENERIC_WRITE,
		0U,
		nullptr,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED |
			SECURITY_SQOS_PRESENT |
			SECURITY_IDENTIFICATION,
		nullptr));
	if(!pipe.valid())
	{
		return std::unexpected(PipeClientFailure {
			.error = PipeClientError::open_failed,
			.win32_error = GetLastError(),
		});
	}

	DWORD server_process_id = 0U;
	if(!GetNamedPipeServerProcessId(pipe.get(), &server_process_id))
	{
		return std::unexpected(PipeClientFailure {
			.error = PipeClientError::server_identity_mismatch,
			.win32_error = GetLastError(),
		});
	}
	if(!server_process_matches(process_id, server_process_id))
	{
		return std::unexpected(PipeClientFailure {
			.error = PipeClientError::server_identity_mismatch,
			.win32_error = ERROR_ACCESS_DENIED,
		});
	}

	const auto deadline =
		std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
	const auto request = protocol::encode({
		.kind = request_kind,
		.payload = {},
	});
	auto mutable_request = request;
	auto result = transfer_exact(pipe.get(), mutable_request, true, deadline);
	if(!result)
	{
		return std::unexpected(result.error());
	}

	std::vector<std::byte> frame(protocol::header_size);
	result = transfer_exact(pipe.get(), frame, false, deadline);
	if(!result)
	{
		return std::unexpected(result.error());
	}
	const std::uint32_t payload_size = wire::read_u32_le(frame, 7U);
	if(payload_size > protocol::maximum_payload_size)
	{
		return std::unexpected(PipeClientFailure {
			.error = PipeClientError::protocol_failed,
			.win32_error = ERROR_BUFFER_OVERFLOW,
		});
	}
	frame.resize(protocol::header_size + payload_size);
	if(payload_size > 0U)
	{
		result = transfer_exact(
			pipe.get(),
			std::span<std::byte>(frame).subspan(protocol::header_size),
			false,
			deadline);
		if(!result)
		{
			return std::unexpected(result.error());
		}
	}

	const auto response = protocol::decode(frame);
	if(!response)
	{
		return std::unexpected(PipeClientFailure {
			.error = PipeClientError::protocol_failed,
			.win32_error = ERROR_INVALID_DATA,
		});
	}
	if(response->kind != response_kind)
	{
		return std::unexpected(PipeClientFailure {
			.error = PipeClientError::unexpected_response,
			.win32_error = ERROR_INVALID_DATA,
		});
	}

	return std::string(
		reinterpret_cast<const char*>(response->payload.data()),
		response->payload.size());
}
}

/// Queries one runtime status pipe and returns its validated JSON payload.
std::expected<std::string, PipeClientFailure> query_status(const DWORD process_id)
{
	return detail::query_status(process_id, pipe_timeout_ms);
}

/// Queries the runtime for its validated Unreal object-array report.
std::expected<std::string, PipeClientFailure> query_objects(const DWORD process_id)
{
	return detail::query_status(
		process_id,
		pipe_timeout_ms,
		protocol::MessageKind::objects_request,
		protocol::MessageKind::objects_response);
}

/// Returns a stable diagnostic name for one status-client failure.
std::string pipe_error_message(const PipeClientFailure& failure)
{
	switch(failure.error)
	{
	case PipeClientError::invalid_process_id:
		return "process ID is invalid";
	case PipeClientError::open_failed:
		return "runtime status pipe is unavailable";
	case PipeClientError::server_identity_mismatch:
		return "runtime status pipe server identity does not match target process";
	case PipeClientError::request_failed:
		return "status request write failed";
	case PipeClientError::timeout:
		return "status request timed out";
	case PipeClientError::response_failed:
		return "status response read failed";
	case PipeClientError::protocol_failed:
		return "status response framing is invalid";
	case PipeClientError::unexpected_response:
		return "runtime returned an unexpected response";
	}
	return "unknown status error";
}
}
