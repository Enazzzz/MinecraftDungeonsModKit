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

	UniqueHandle(const UniqueHandle&) = delete;
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

/// Holds a self-relative descriptor and attributes that reference it.
struct PipeSecurity
{
	LocalAllocation descriptor;
	SECURITY_ATTRIBUTES attributes;
};

/// Names the outcome of one cancellable pipe operation.
enum class IoResult
{
	success,
	stopped,
	failed,
};

/// Throws a system error carrying the current Win32 failure code.
[[noreturn]] void throw_last_error(const char* operation)
{
	throw std::system_error(
		static_cast<int>(GetLastError()),
		std::system_category(),
		operation);
}

/// Builds a protected pipe DACL granting access only to the current logon SID.
PipeSecurity current_user_pipe_security()
{
	HANDLE raw_token = nullptr;
	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token))
	{
		throw_last_error("OpenProcessToken");
	}
	UniqueHandle token(raw_token);

	DWORD token_size = 0U;
	GetTokenInformation(token.get(), TokenUser, nullptr, 0U, &token_size);
	if(GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		throw_last_error("GetTokenInformation(size)");
	}

	std::vector<std::byte> token_buffer(token_size);
	if(!GetTokenInformation(
		   token.get(),
		   TokenUser,
		   token_buffer.data(),
		   token_size,
		   &token_size))
	{
		throw_last_error("GetTokenInformation");
	}

	const auto* token_user = reinterpret_cast<const TOKEN_USER*>(token_buffer.data());
	LPWSTR raw_sid_text = nullptr;
	if(!ConvertSidToStringSidW(token_user->User.Sid, &raw_sid_text))
	{
		throw_last_error("ConvertSidToStringSidW");
	}
	LocalAllocation sid_text(raw_sid_text);

	const std::wstring sddl =
		L"D:P(A;;GA;;;" + std::wstring(static_cast<const wchar_t*>(sid_text.get())) + L")";
	PSECURITY_DESCRIPTOR raw_descriptor = nullptr;
	if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(
		   sddl.c_str(),
		   SDDL_REVISION_1,
		   &raw_descriptor,
		   nullptr))
	{
		throw_last_error("ConvertStringSecurityDescriptorToSecurityDescriptorW");
	}

	LocalAllocation descriptor(raw_descriptor);
	SECURITY_ATTRIBUTES attributes {
		.nLength = sizeof(SECURITY_ATTRIBUTES),
		.lpSecurityDescriptor = descriptor.get(),
		.bInheritHandle = FALSE,
	};
	return PipeSecurity {
		.descriptor = std::move(descriptor),
		.attributes = attributes,
	};
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
		(void)WaitForSingleObject(operation.hEvent, INFINITE);
		return IoResult::stopped;
	}

	if(wait_result != WAIT_OBJECT_0 + 1U ||
	   !GetOverlappedResult(pipe, &operation, &transferred, FALSE))
	{
		return IoResult::failed;
	}

	return IoResult::success;
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
		UniqueHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
		if(!event.valid())
		{
			return IoResult::failed;
		}

		OVERLAPPED operation {};
		operation.hEvent = event.get();
		DWORD transferred = 0U;
		const DWORD remaining = static_cast<DWORD>(bytes.size() - offset);
		const BOOL completed = writing
			? WriteFile(pipe, bytes.data() + offset, remaining, &transferred, &operation)
			: ReadFile(pipe, bytes.data() + offset, remaining, &transferred, &operation);

		if(!completed)
		{
			if(GetLastError() != ERROR_IO_PENDING)
			{
				return IoResult::failed;
			}

			const IoResult result = await_operation(pipe, operation, stop_event, transferred);
			if(result != IoResult::success)
			{
				return result;
			}
		}

		if(transferred == 0U)
		{
			return IoResult::failed;
		}
		offset += transferred;
	}

	return IoResult::success;
}

/// Accepts one client while allowing shutdown to cancel the pending connection.
IoResult connect_client(const HANDLE pipe, const HANDLE stop_event)
{
	UniqueHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
	if(!event.valid())
	{
		return IoResult::failed;
	}

	OVERLAPPED operation {};
	operation.hEvent = event.get();
	if(ConnectNamedPipe(pipe, &operation))
	{
		return IoResult::success;
	}

	const DWORD error = GetLastError();
	if(error == ERROR_PIPE_CONNECTED)
	{
		return IoResult::success;
	}
	if(error != ERROR_IO_PENDING)
	{
		return IoResult::failed;
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
	if(result != IoResult::success)
	{
		return result;
	}

	const std::uint32_t payload_size = mcd::wire::read_u32_le(frame, 7U);
	if(payload_size > mcd::protocol::maximum_payload_size)
	{
		return IoResult::failed;
	}

	frame.resize(mcd::protocol::header_size + payload_size);
	if(payload_size == 0U)
	{
		return IoResult::success;
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

namespace mcd::runtime
{
/// Stores the platform resources and immutable status identity of a pipe server.
class PipeServer::Impl
{
public:
	/// Creates the cooperative stop event and records the selected profile.
	explicit Impl(const std::string_view profile_id)
		: stop_event_(CreateEventW(nullptr, TRUE, FALSE, nullptr)),
		  profile_id_(profile_id)
	{
		if(!stop_event_.valid())
		{
			throw_last_error("CreateEventW");
		}
	}

	/// Serves sequential trusted clients until shutdown is signaled.
	[[nodiscard]] DWORD run() noexcept
	{
		try
		{
			const PipeSecurity security = current_user_pipe_security();
			while(WaitForSingleObject(stop_event_.get(), 0U) == WAIT_TIMEOUT)
			{
				const DWORD open_mode =
					PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE;
				const DWORD pipe_mode =
					PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
				UniqueHandle pipe(CreateNamedPipeW(
					pipe_name().c_str(),
					open_mode,
					pipe_mode,
					1U,
					static_cast<DWORD>(
						mcd::protocol::header_size + mcd::protocol::maximum_payload_size),
					static_cast<DWORD>(
						mcd::protocol::header_size + mcd::protocol::maximum_payload_size),
					0U,
					const_cast<SECURITY_ATTRIBUTES*>(&security.attributes)));
				if(!pipe.valid())
				{
					return GetLastError();
				}

				const IoResult connection = connect_client(pipe.get(), stop_event_.get());
				if(connection == IoResult::stopped)
				{
					return ERROR_SUCCESS;
				}
				if(connection == IoResult::failed)
				{
					return GetLastError();
				}

				serve_client(pipe.get());
				DisconnectNamedPipe(pipe.get());
			}
			return ERROR_SUCCESS;
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
		if(read_frame(pipe, stop_event_.get(), frame) != IoResult::success)
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
		(void)transfer_exact(pipe, bytes, true, stop_event_.get());
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
