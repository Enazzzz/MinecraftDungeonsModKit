#pragma once

#include <cstddef>
#include <memory>
#include <string_view>
#include <vector>

#include <windows.h>

namespace mcd::runtime
{
namespace detail
{
/// Names the outcome category of one cancellable pipe operation.
enum class IoStatus
{
	success,
	stopped,
	failed,
};

/// Preserves an operation outcome together with its originating Win32 error.
struct IoResult
{
	IoStatus status;
	DWORD error;
	bool operation_pending = false;
};

/// Returns a failed operation result retaining the supplied Win32 error.
[[nodiscard]] constexpr IoResult io_failure(const DWORD error) noexcept
{
	return {.status = IoStatus::failed, .error = error};
}

/// Resolves one bounded CancelIoEx attempt without losing its source error.
[[nodiscard]] IoResult resolve_cancellation(
	BOOL cancel_succeeded,
	DWORD cancel_error,
	DWORD completion_wait,
	DWORD wait_error,
	BOOL completion_succeeded,
	DWORD completion_error) noexcept;

/// Builds a self-relative pipe descriptor for the current logon session.
[[nodiscard]] std::vector<std::byte> build_pipe_security_descriptor();
}

/// Serves bounded status requests over a current-user-only named pipe.
class PipeServer
{
public:
	/// Creates a stopped server for the current process and build profile.
	explicit PipeServer(std::string_view profile_id);

	/// Releases the server stop event and any related operating-system state.
	~PipeServer() noexcept;

	/// Prevents duplicating ownership of the server implementation.
	PipeServer(const PipeServer&) = delete;

	/// Prevents copy assignment of the server implementation.
	PipeServer& operator=(const PipeServer&) = delete;

	/// Prevents moving a server while asynchronous operations reference it.
	PipeServer(PipeServer&&) = delete;

	/// Prevents move assignment while asynchronous operations reference it.
	PipeServer& operator=(PipeServer&&) = delete;

	/// Serves one local client at a time until shutdown is requested.
	[[nodiscard]] DWORD run() noexcept;

	/// Signals all pending server operations to stop.
	void request_stop() noexcept;

private:
	class Impl;
	std::unique_ptr<Impl> implementation_;
};
}
