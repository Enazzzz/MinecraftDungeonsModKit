#include "mcd/runtime/pipe_server.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <sddl.h>

#include "mcd/protocol.hpp"
#include "mcd/wire.hpp"

namespace
{
/// Owns one closeable Windows kernel handle.
class UniqueHandle
{
public:
	/// Takes ownership of a possibly invalid handle.
	explicit UniqueHandle(HANDLE handle = nullptr) noexcept
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

	/// Prevents duplicating ownership of a kernel handle.
	UniqueHandle(const UniqueHandle&) = delete;

	/// Prevents copy assignment of a kernel handle.
	UniqueHandle& operator=(const UniqueHandle&) = delete;

	/// Transfers handle ownership from another wrapper.
	UniqueHandle(UniqueHandle&& other) noexcept
		: handle_(std::exchange(other.handle_, nullptr))
	{
	}

	/// Replaces this handle with ownership from another wrapper.
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

	/// Returns whether the wrapper owns a usable handle.
	[[nodiscard]] bool valid() const noexcept
	{
		return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
	}

private:
	HANDLE handle_;
};

/// Frees memory returned by Windows local-allocation APIs.
struct LocalFreeDeleter
{
	/// Releases one local-allocation pointer.
	void operator()(void* pointer) const noexcept
	{
		if(pointer)
		{
			LocalFree(pointer);
		}
	}
};

using LocalAllocation = std::unique_ptr<void, LocalFreeDeleter>;

using mcd::runtime::detail::IoResult;
using mcd::runtime::detail::IoStatus;
using mcd::runtime::detail::io_failure;

/// Throws a system error carrying a previously captured Win32 failure code.
[[noreturn]] void throw_win32_error(const DWORD error, const char* operation)
{
	throw std::system_error(
		static_cast<int>(error),
		std::system_category(),
		operation);
}

/// Returns token information bytes or throws with the originating Win32 error.
std::vector<std::byte> token_information(
	const HANDLE token,
	const TOKEN_INFORMATION_CLASS information_class)
{
	DWORD size = 0U;
	if(GetTokenInformation(token, information_class, nullptr, 0U, &size))
	{
		throw std::runtime_error("Token information unexpectedly had no payload.");
	}

	const DWORD size_error = GetLastError();
	if(size_error != ERROR_INSUFFICIENT_BUFFER)
	{
		throw_win32_error(size_error, "GetTokenInformation(size)");
	}

	std::vector<std::byte> buffer(size);
	if(!GetTokenInformation(
		   token,
		   information_class,
		   buffer.data(),
		   size,
		   &size))
	{
		const DWORD error = GetLastError();
		throw_win32_error(error, "GetTokenInformation");
	}
	return buffer;
}

/// Converts one valid SID to SDDL text.
std::wstring sid_string(const PSID sid)
{
	LPWSTR raw_sid_text = nullptr;
	if(!ConvertSidToStringSidW(sid, &raw_sid_text))
	{
		const DWORD error = GetLastError();
		throw_win32_error(error, "ConvertSidToStringSidW");
	}
	LocalAllocation sid_text(raw_sid_text);
	return std::wstring(static_cast<const wchar_t*>(sid_text.get()));
}

/// Returns the current token's group marked as its logon SID.
PSID logon_sid(const std::vector<std::byte>& groups_buffer)
{
	const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(groups_buffer.data());
	for(DWORD index = 0U; index < groups->GroupCount; ++index)
	{
		if((groups->Groups[index].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
		{
			return groups->Groups[index].Sid;
		}
	}
	throw std::runtime_error("Current token does not contain a logon SID.");
}

/// Returns the process-specific local control pipe name.
std::wstring pipe_name()
{
	return L"\\\\.\\pipe\\mcd-runtime-" + std::to_wstring(GetCurrentProcessId());
}

/// Waits for one overlapped operation or cooperative shutdown.
IoResult await_operation(
	const HANDLE pipe,
	OVERLAPPED& operation,
	const HANDLE stop_event,
	DWORD& transferred)
{
	const std::array<HANDLE, 2> handles {stop_event, operation.hEvent};
	const DWORD wait_result = WaitForMultipleObjects(
		static_cast<DWORD>(handles.size()),
		handles.data(),
		FALSE,
		INFINITE);
	if(wait_result == WAIT_OBJECT_0)
	{
		CancelIoEx(pipe, &operation);
		const DWORD completion_wait = WaitForSingleObject(operation.hEvent, INFINITE);
		if(completion_wait == WAIT_FAILED)
		{
			return io_failure(GetLastError());
		}
		return {.status = IoStatus::stopped, .error = ERROR_OPERATION_ABORTED};
	}

	if(wait_result == WAIT_FAILED)
	{
		return io_failure(GetLastError());
	}
	if(wait_result != WAIT_OBJECT_0 + 1U)
	{
		return io_failure(ERROR_GEN_FAILURE);
	}
	if(!GetOverlappedResult(pipe, &operation, &transferred, FALSE))
	{
		return io_failure(GetLastError());
	}

	return {.status = IoStatus::success, .error = ERROR_SUCCESS};
}

/// Transfers exactly one bounded byte span unless stopped or disconnected.
IoResult transfer_exact(
	const HANDLE pipe,
	const std::span<std::byte> bytes,
	const bool writing,
	const HANDLE stop_event)
{
	std::size_t offset = 0U;
	while(offset < bytes.size())
	{
		const HANDLE raw_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		if(raw_event == nullptr)
		{
			return io_failure(GetLastError());
		}
		UniqueHandle event(raw_event);

		OVERLAPPED operation {};
		operation.hEvent = event.get();
		DWORD transferred = 0U;
		const DWORD remaining = static_cast<DWORD>(bytes.size() - offset);
		const BOOL completed = writing
			? WriteFile(pipe, bytes.data() + offset, remaining, nullptr, &operation)
			: ReadFile(pipe, bytes.data() + offset, remaining, nullptr, &operation);

		if(!completed)
		{
			const DWORD error = GetLastError();
			if(error != ERROR_IO_PENDING)
			{
				return io_failure(error);
			}

			const IoResult result = await_operation(pipe, operation, stop_event, transferred);
			if(result.status != IoStatus::success)
			{
				return result;
			}
		}
		else if(!GetOverlappedResult(pipe, &operation, &transferred, TRUE))
		{
			return io_failure(GetLastError());
		}

		if(transferred == 0U)
		{
			return io_failure(ERROR_BROKEN_PIPE);
		}
		offset += transferred;
	}

	return {.status = IoStatus::success, .error = ERROR_SUCCESS};
}

/// Accepts one client while allowing shutdown to cancel the pending connection.
IoResult connect_client(const HANDLE pipe, const HANDLE stop_event)
{
	const HANDLE raw_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	if(raw_event == nullptr)
	{
		return io_failure(GetLastError());
	}
	UniqueHandle event(raw_event);

	OVERLAPPED operation {};
	operation.hEvent = event.get();
	if(ConnectNamedPipe(pipe, &operation))
	{
		return {.status = IoStatus::success, .error = ERROR_SUCCESS};
	}

	const DWORD error = GetLastError();
	if(error == ERROR_PIPE_CONNECTED)
	{
		return {.status = IoStatus::success, .error = ERROR_SUCCESS};
	}
	if(error != ERROR_IO_PENDING)
	{
		return io_failure(error);
	}

	DWORD transferred = 0U;
	return await_operation(pipe, operation, stop_event, transferred);
}

/// Reads one complete frame after bounding its declared payload length.
IoResult read_frame(
	const HANDLE pipe,
	const HANDLE stop_event,
	std::vector<std::byte>& frame)
{
	frame.assign(mcd::protocol::header_size, std::byte {0});
	IoResult result = transfer_exact(pipe, frame, false, stop_event);
	if(result.status != IoStatus::success)
	{
		return result;
	}

	const std::uint32_t payload_size = mcd::wire::read_u32_le(frame, 7U);
	if(payload_size > mcd::protocol::maximum_payload_size)
	{
		return io_failure(ERROR_BUFFER_OVERFLOW);
	}

	frame.resize(mcd::protocol::header_size + payload_size);
	if(payload_size == 0U)
	{
		return {.status = IoStatus::success, .error = ERROR_SUCCESS};
	}

	return transfer_exact(
		pipe,
		std::span<std::byte>(frame).subspan(mcd::protocol::header_size),
		false,
		stop_event);
}

/// Returns the JSON status payload exposed to trusted local clients.
std::vector<std::byte> status_payload(const std::string_view profile_id)
{
	const std::string json =
		"{\"state\":\"ready\",\"runtime_version\":\"0.1.0\",\"profile_id\":\"" +
		std::string(profile_id) + "\",\"process_id\":" +
		std::to_string(GetCurrentProcessId()) + "}";
	const auto chars = std::span {json.data(), json.size()};
	const auto bytes = std::as_bytes(chars);
	return std::vector<std::byte>(bytes.begin(), bytes.end());
}
}

namespace mcd::runtime::detail
{
/// Builds a self-relative pipe descriptor for the current logon session.
std::vector<std::byte> build_pipe_security_descriptor()
{
	HANDLE raw_token = nullptr;
	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token))
	{
		const DWORD error = GetLastError();
		throw_win32_error(error, "OpenProcessToken");
	}
	UniqueHandle token(raw_token);

	const auto groups_buffer = token_information(token.get(), TokenGroups);
	const auto owner_buffer = token_information(token.get(), TokenOwner);
	const auto primary_group_buffer = token_information(token.get(), TokenPrimaryGroup);
	const auto* owner = reinterpret_cast<const TOKEN_OWNER*>(owner_buffer.data());
	const auto* primary_group =
		reinterpret_cast<const TOKEN_PRIMARY_GROUP*>(primary_group_buffer.data());
	const std::wstring sddl =
		L"O:" + sid_string(owner->Owner) +
		L"G:" + sid_string(primary_group->PrimaryGroup) +
		L"D:P(A;;GRGW;;;" + sid_string(logon_sid(groups_buffer)) + L")";

	PSECURITY_DESCRIPTOR raw_descriptor = nullptr;
	if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(
		   sddl.c_str(),
		   SDDL_REVISION_1,
		   &raw_descriptor,
		   nullptr))
	{
		const DWORD error = GetLastError();
		throw_win32_error(error, "ConvertStringSecurityDescriptorToSecurityDescriptorW");
	}
	LocalAllocation descriptor(raw_descriptor);

	const DWORD descriptor_size = GetSecurityDescriptorLength(descriptor.get());
	const auto* bytes = static_cast<const std::byte*>(descriptor.get());
	return std::vector<std::byte>(bytes, bytes + descriptor_size);
}
}

namespace mcd::runtime
{
/// Stores the platform resources and immutable status identity of a pipe server.
class PipeServer::Impl
{
public:
	/// Creates the cooperative stop event and records the selected profile.
	explicit Impl(const std::string_view profile_id)
		: profile_id_(profile_id)
	{
		const HANDLE raw_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		if(raw_stop_event == nullptr)
		{
			const DWORD error = GetLastError();
			throw_win32_error(error, "CreateEventW");
		}
		stop_event_ = UniqueHandle(raw_stop_event);
	}

	/// Serves sequential trusted clients until shutdown is signaled.
	[[nodiscard]] DWORD run() noexcept
	{
		try
		{
			auto descriptor = detail::build_pipe_security_descriptor();
			SECURITY_ATTRIBUTES security {
				.nLength = sizeof(SECURITY_ATTRIBUTES),
				.lpSecurityDescriptor = descriptor.data(),
				.bInheritHandle = FALSE,
			};
			while(true)
			{
				const DWORD stop_state = WaitForSingleObject(stop_event_.get(), 0U);
				if(stop_state == WAIT_OBJECT_0)
				{
					return ERROR_SUCCESS;
				}
				if(stop_state == WAIT_FAILED)
				{
					return GetLastError();
				}

				const DWORD open_mode =
					PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE;
				const DWORD pipe_mode =
					PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
				const HANDLE raw_pipe = CreateNamedPipeW(
					pipe_name().c_str(),
					open_mode,
					pipe_mode,
					1U,
					static_cast<DWORD>(
						mcd::protocol::header_size + mcd::protocol::maximum_payload_size),
					static_cast<DWORD>(
						mcd::protocol::header_size + mcd::protocol::maximum_payload_size),
					0U,
					&security);
				if(raw_pipe == INVALID_HANDLE_VALUE)
				{
					return GetLastError();
				}
				UniqueHandle pipe(raw_pipe);

				const IoResult connection = connect_client(pipe.get(), stop_event_.get());
				if(connection.status == IoStatus::stopped)
				{
					return ERROR_SUCCESS;
				}
				if(connection.status == IoStatus::failed)
				{
					return connection.error;
				}

				serve_client(pipe.get());
				DisconnectNamedPipe(pipe.get());
			}
		}
		catch(const std::system_error& error)
		{
			return static_cast<DWORD>(error.code().value());
		}
		catch(...)
		{
			return ERROR_GEN_FAILURE;
		}
	}

	/// Signals all pending operations through the manual-reset stop event.
	void request_stop() noexcept
	{
		SetEvent(stop_event_.get());
	}

private:
	/// Handles at most one status request for the connected client.
	void serve_client(const HANDLE pipe) noexcept
	{
		std::vector<std::byte> frame;
		const IoResult read_result = read_frame(pipe, stop_event_.get(), frame);
		if(read_result.status != IoStatus::success)
		{
			return;
		}

		const auto request = mcd::protocol::decode(frame);
		if(!request ||
		   request->kind != mcd::protocol::MessageKind::status_request ||
		   !request->payload.empty())
		{
			return;
		}

		const mcd::protocol::Message response {
			.kind = mcd::protocol::MessageKind::status_response,
			.payload = status_payload(profile_id_),
		};
		std::vector<std::byte> bytes = mcd::protocol::encode(response);
		const IoResult write_result = transfer_exact(pipe, bytes, true, stop_event_.get());
		if(write_result.status != IoStatus::success)
		{
			return;
		}

		std::byte trailing_byte {};
		(void)transfer_exact(
			pipe,
			std::span<std::byte>(&trailing_byte, 1U),
			false,
			stop_event_.get());
	}

	UniqueHandle stop_event_;
	std::string profile_id_;
};

/// Creates a stopped server for the current process and build profile.
PipeServer::PipeServer(const std::string_view profile_id)
	: implementation_(std::make_unique<Impl>(profile_id))
{
}

/// Releases the server stop event and any related operating-system state.
PipeServer::~PipeServer() noexcept = default;

/// Serves one local client at a time until shutdown is requested.
DWORD PipeServer::run() noexcept
{
	return implementation_->run();
}

/// Signals all pending server operations to stop.
void PipeServer::request_stop() noexcept
{
	implementation_->request_stop();
}
}
