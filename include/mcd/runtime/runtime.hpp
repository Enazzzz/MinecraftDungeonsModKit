#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

#include <windows.h>

namespace mcd::runtime
{
class PipeServer;

/// Names every stable phase in the injected runtime lifecycle.
enum class State
{
	dormant,
	validating,
	ready,
	unsupported_build,
	failed,
	stopping,
	stopped,
};

/// Enforces the host-independent runtime lifecycle transitions.
class RuntimeStateMachine
{
public:
	/// Returns the current lifecycle state.
	[[nodiscard]] State state() const noexcept;

	/// Begins executable validation from the dormant state.
	[[nodiscard]] bool transition_to_validating() noexcept;

	/// Records successful validation and starts serving requests.
	[[nodiscard]] bool transition_to_ready() noexcept;

	/// Records that the host executable has no matching build profile.
	[[nodiscard]] bool reject_build() noexcept;

	/// Records an initialization or server failure.
	[[nodiscard]] bool fail() noexcept;

	/// Starts shutdown from any active or failed state.
	[[nodiscard]] bool request_stop() noexcept;

	/// Completes shutdown after all owned resources are released.
	[[nodiscard]] bool transition_to_stopped() noexcept;

private:
	std::atomic<State> state_ {State::dormant};
};

/// Reads the supported build's name pool and chunked UObject array.
[[nodiscard]] std::string discover_host_objects(std::string_view profile_id);

/// Owns process validation and the local control-server lifecycle.
class Runtime
{
public:
	/// Returns the process-wide runtime instance.
	[[nodiscard]] static Runtime& instance() noexcept;

	/// Validates the host and serves control requests until stopped.
	[[nodiscard]] DWORD start(HMODULE module) noexcept;

	/// Requests cooperative shutdown of the active server.
	void request_stop() noexcept;

	/// Returns the current process-wide lifecycle state.
	[[nodiscard]] State state() const noexcept;

private:
	/// Constructs the process-wide runtime in the dormant state.
	Runtime() = default;

	/// Releases the process-wide runtime after owned resources stop.
	~Runtime();

	mutable std::mutex server_mutex_;
	std::unique_ptr<PipeServer> server_;
	RuntimeStateMachine state_ {};
};
}
