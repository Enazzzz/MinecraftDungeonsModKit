#include <chrono>
#include <future>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

#include "mcd/runtime/pipe_server.hpp"
#include "mcd/runtime/runtime.hpp"

namespace
{
/// Throws a deterministic test failure with a human-readable message.
[[noreturn]] void fail(const std::string_view message)
{
	throw std::runtime_error(std::string(message));
}

/// Fails fast when a required test condition is false.
void require(const bool condition, const std::string_view message)
{
	if(!condition)
	{
		fail(message);
	}
}

/// Expands one active test oracle check with its source expression text.
#define REQUIRE(condition) require(static_cast<bool>(condition), #condition)

/// Verifies that a build mismatch cannot transition to ready.
void test_runtime_rejects_unknown_build()
{
	mcd::runtime::RuntimeStateMachine state;
	REQUIRE(state.transition_to_validating());
	REQUIRE(state.reject_build());
	REQUIRE(state.state() == mcd::runtime::State::unsupported_build);
	REQUIRE(!state.transition_to_ready());
}

/// Verifies the successful initialization sequence is deterministic.
void test_runtime_reaches_ready_once()
{
	mcd::runtime::RuntimeStateMachine state;
	REQUIRE(state.state() == mcd::runtime::State::dormant);
	REQUIRE(state.transition_to_validating());
	REQUIRE(!state.transition_to_validating());
	REQUIRE(state.transition_to_ready());
	REQUIRE(state.state() == mcd::runtime::State::ready);
	REQUIRE(!state.reject_build());
}

/// Verifies a ready runtime follows an idempotent stop sequence.
void test_ready_runtime_stops_cleanly()
{
	mcd::runtime::RuntimeStateMachine state;
	REQUIRE(state.transition_to_validating());
	REQUIRE(state.transition_to_ready());
	REQUIRE(state.request_stop());
	REQUIRE(state.state() == mcd::runtime::State::stopping);
	REQUIRE(!state.request_stop());
	REQUIRE(state.transition_to_stopped());
	REQUIRE(state.state() == mcd::runtime::State::stopped);
	REQUIRE(!state.transition_to_ready());
}

/// Verifies initialization failures can unwind directly to stopped.
void test_failed_runtime_unwinds()
{
	mcd::runtime::RuntimeStateMachine state;
	REQUIRE(state.transition_to_validating());
	REQUIRE(state.fail());
	REQUIRE(state.state() == mcd::runtime::State::failed);
	REQUIRE(state.request_stop());
	REQUIRE(state.transition_to_stopped());
	REQUIRE(state.state() == mcd::runtime::State::stopped);
}

/// Verifies shutdown cancels a pending named-pipe connection without hanging.
void test_pipe_server_stops_while_waiting()
{
	mcd::runtime::PipeServer server("test-profile");
	auto result = std::async(std::launch::async, [&server] {
		return server.run();
	});

	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	server.request_stop();
	REQUIRE(result.wait_for(std::chrono::seconds(2)) == std::future_status::ready);
	REQUIRE(result.get() == ERROR_SUCCESS);
}
}

/// Runs the host-independent runtime lifecycle regression tests.
int main()
{
	test_runtime_rejects_unknown_build();
	test_runtime_reaches_ready_once();
	test_ready_runtime_stops_cleanly();
	test_failed_runtime_unwinds();
	test_pipe_server_stops_while_waiting();
	return 0;
}
