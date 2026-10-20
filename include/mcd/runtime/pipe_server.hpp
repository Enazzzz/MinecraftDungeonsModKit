#pragma once

#include <memory>
#include <string_view>

#include <windows.h>

namespace mcd::runtime
{
/// Serves bounded status requests over a current-user-only named pipe.
class PipeServer
{
public:
	/// Creates a stopped server for the current process and build profile.
	explicit PipeServer(std::string_view profile_id);

	/// Releases the server stop event and any related operating-system state.
	~PipeServer() noexcept;

	PipeServer(const PipeServer&) = delete;
	PipeServer& operator=(const PipeServer&) = delete;
	PipeServer(PipeServer&&) = delete;
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
