#include "mcd/runtime/runtime.hpp"

#include <filesystem>
#include <system_error>
#include <vector>

#include "mcd/build_identity.hpp"
#include "mcd/runtime/pipe_server.hpp"

namespace
{
/// Returns the absolute path of the executable hosting the runtime.
std::filesystem::path host_executable_path()
{
	std::vector<wchar_t> buffer(32'768U);
	DWORD length = static_cast<DWORD>(buffer.size());
	if(!QueryFullProcessImageNameW(GetCurrentProcess(), 0U, buffer.data(), &length))
	{
		throw std::system_error(
			static_cast<int>(GetLastError()),
			std::system_category(),
			"QueryFullProcessImageNameW");
	}

	return std::filesystem::path(std::wstring_view(buffer.data(), length));
}
}

namespace mcd::runtime
{
/// Returns the current lifecycle state.
State RuntimeStateMachine::state() const noexcept
{
	return state_.load(std::memory_order_acquire);
}

/// Begins executable validation from the dormant state.
bool RuntimeStateMachine::transition_to_validating() noexcept
{
	State expected = State::dormant;
	return state_.compare_exchange_strong(expected, State::validating);
}

/// Records successful validation and starts serving requests.
bool RuntimeStateMachine::transition_to_ready() noexcept
{
	State expected = State::validating;
	return state_.compare_exchange_strong(expected, State::ready);
}

/// Records that the host executable has no matching build profile.
bool RuntimeStateMachine::reject_build() noexcept
{
	State expected = State::validating;
	return state_.compare_exchange_strong(expected, State::unsupported_build);
}

/// Records an initialization or server failure.
bool RuntimeStateMachine::fail() noexcept
{
	State expected = State::validating;
	if(state_.compare_exchange_strong(expected, State::failed))
	{
		return true;
	}

	expected = State::ready;
	return state_.compare_exchange_strong(expected, State::failed);
}

/// Starts shutdown from any active or failed state.
bool RuntimeStateMachine::request_stop() noexcept
{
	State expected = State::validating;
	if(state_.compare_exchange_strong(expected, State::stopping))
	{
		return true;
	}

	expected = State::ready;
	if(state_.compare_exchange_strong(expected, State::stopping))
	{
		return true;
	}

	expected = State::failed;
	return state_.compare_exchange_strong(expected, State::stopping);
}

/// Completes shutdown after all owned resources are released.
bool RuntimeStateMachine::transition_to_stopped() noexcept
{
	State expected = State::stopping;
	return state_.compare_exchange_strong(expected, State::stopped);
}

/// Returns the process-wide runtime instance.
Runtime& Runtime::instance() noexcept
{
	static Runtime runtime;
	return runtime;
}

/// Releases the process-wide runtime after owned resources stop.
Runtime::~Runtime() = default;

/// Validates the host and serves control requests until stopped.
DWORD Runtime::start(const HMODULE module) noexcept
{
	(void)module;
	if(!state_.transition_to_validating())
	{
		return ERROR_ALREADY_INITIALIZED;
	}

	try
	{
		const std::filesystem::path path = host_executable_path();
		std::error_code size_error;
		const std::uintmax_t image_size = std::filesystem::file_size(path, size_error);
		if(size_error)
		{
			throw std::system_error(size_error, "file_size");
		}

		const auto digest = sha256_file(path);
		if(!digest)
		{
			throw std::runtime_error("Unable to hash the host executable.");
		}

		const auto profile = identify_build(image_size, *digest);
		if(!profile)
		{
			(void)state_.reject_build();
			return ERROR_NOT_SUPPORTED;
		}

		PipeServer* server = nullptr;
		{
			const std::scoped_lock lock(server_mutex_);
			server_ = std::make_unique<PipeServer>(profile->id);
			server = server_.get();
		}

		if(!state_.transition_to_ready())
		{
			const std::scoped_lock lock(server_mutex_);
			server_.reset();
			(void)state_.transition_to_stopped();
			return ERROR_CANCELLED;
		}

		const DWORD result = server->run();
		{
			const std::scoped_lock lock(server_mutex_);
			server_.reset();
		}

		if(result != ERROR_SUCCESS)
		{
			(void)state_.fail();
		}

		(void)state_.request_stop();
		(void)state_.transition_to_stopped();
		return result;
	}
	catch(...)
	{
		{
			const std::scoped_lock lock(server_mutex_);
			server_.reset();
		}
		(void)state_.fail();
		(void)state_.request_stop();
		(void)state_.transition_to_stopped();
		return ERROR_GEN_FAILURE;
	}
}

/// Requests cooperative shutdown of the active server.
void Runtime::request_stop() noexcept
{
	(void)state_.request_stop();
	const std::scoped_lock lock(server_mutex_);
	if(server_)
	{
		server_->request_stop();
	}
}

/// Returns the current process-wide lifecycle state.
State Runtime::state() const noexcept
{
	return state_.state();
}
}
