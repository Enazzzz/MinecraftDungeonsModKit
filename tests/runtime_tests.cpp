#include <array>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <future>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "mcd/protocol.hpp"
#include "mcd/runtime/pipe_server.hpp"
#include "mcd/runtime/runtime.hpp"
#include "mcd/wire.hpp"

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

/// Returns the fixed control pipe name for this test process.
std::wstring test_pipe_name()
{
	return L"\\\\.\\pipe\\mcd-runtime-" + std::to_wstring(GetCurrentProcessId());
}

/// Waits until the server has created a connectable pipe instance.
void wait_for_pipe(const std::chrono::steady_clock::time_point deadline)
{
	while(std::chrono::steady_clock::now() < deadline)
	{
		if(WaitNamedPipeW(test_pipe_name().c_str(), 20U))
		{
			return;
		}

		const DWORD error = GetLastError();
		REQUIRE(error == ERROR_FILE_NOT_FOUND || error == ERROR_SEM_TIMEOUT);
	}

	fail("pipe readiness deadline expired");
}

/// Connects a local test client before an explicit deadline.
HANDLE connect_client(const std::chrono::steady_clock::time_point deadline)
{
	while(std::chrono::steady_clock::now() < deadline)
	{
		const HANDLE pipe = CreateFileW(
			test_pipe_name().c_str(),
			GENERIC_READ | GENERIC_WRITE,
			0U,
			nullptr,
			OPEN_EXISTING,
			0U,
			nullptr);
		if(pipe != INVALID_HANDLE_VALUE)
		{
			return pipe;
		}

		const DWORD error = GetLastError();
		REQUIRE(
			error == ERROR_FILE_NOT_FOUND ||
			error == ERROR_PIPE_BUSY);
		std::this_thread::sleep_for(std::chrono::milliseconds(2));
	}

	fail("pipe connection deadline expired");
}

/// Writes every byte in a client buffer.
void write_all(const HANDLE pipe, const std::span<const std::byte> bytes)
{
	std::size_t offset = 0U;
	while(offset < bytes.size())
	{
		DWORD transferred = 0U;
		REQUIRE(WriteFile(
			pipe,
			bytes.data() + offset,
			static_cast<DWORD>(bytes.size() - offset),
			&transferred,
			nullptr));
		REQUIRE(transferred > 0U);
		offset += transferred;
	}
}

/// Reads every requested byte while accepting partial byte-mode pipe reads.
void read_all(const HANDLE pipe, const std::span<std::byte> bytes)
{
	std::size_t offset = 0U;
	while(offset < bytes.size())
	{
		DWORD transferred = 0U;
		REQUIRE(ReadFile(
			pipe,
			bytes.data() + offset,
			static_cast<DWORD>(bytes.size() - offset),
			&transferred,
			nullptr));
		REQUIRE(transferred > 0U);
		offset += transferred;
	}
}

/// Reads exactly one complete bounded response frame.
std::vector<std::byte> read_response(const HANDLE pipe)
{
	std::vector<std::byte> frame(mcd::protocol::header_size);
	read_all(pipe, frame);

	const std::uint32_t payload_size = mcd::wire::read_u32_le(frame, 7U);
	REQUIRE(payload_size <= mcd::protocol::maximum_payload_size);
	frame.resize(frame.size() + payload_size);
	read_all(
		pipe,
		std::span<std::byte>(frame).subspan(mcd::protocol::header_size));
	return frame;
}

/// Waits until the server rejects and disconnects one malformed client.
void wait_for_disconnect(
	const HANDLE pipe,
	const std::chrono::steady_clock::time_point deadline)
{
	while(std::chrono::steady_clock::now() < deadline)
	{
		DWORD available = 0U;
		if(!PeekNamedPipe(pipe, nullptr, 0U, nullptr, &available, nullptr))
		{
			REQUIRE(
				GetLastError() == ERROR_BROKEN_PIPE ||
				GetLastError() == ERROR_PIPE_NOT_CONNECTED);
			return;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(2));
	}

	fail("pipe disconnect deadline expired");
}

/// Returns token information bytes for one requested information class.
std::vector<std::byte> token_information(
	const HANDLE token,
	const TOKEN_INFORMATION_CLASS information_class)
{
	DWORD size = 0U;
	GetTokenInformation(token, information_class, nullptr, 0U, &size);
	REQUIRE(GetLastError() == ERROR_INSUFFICIENT_BUFFER);
	std::vector<std::byte> bytes(size);
	REQUIRE(GetTokenInformation(
		token,
		information_class,
		bytes.data(),
		size,
		&size));
	return bytes;
}

/// Returns the current token group marked as the logon SID.
PSID current_logon_sid(const std::vector<std::byte>& groups_buffer)
{
	const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(groups_buffer.data());
	for(DWORD index = 0U; index < groups->GroupCount; ++index)
	{
		if((groups->Groups[index].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
		{
			return groups->Groups[index].Sid;
		}
	}

	fail("current token has no logon SID");
}

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

	wait_for_pipe(std::chrono::steady_clock::now() + std::chrono::seconds(2));
	server.request_stop();
	REQUIRE(result.wait_for(std::chrono::seconds(2)) == std::future_status::ready);
	REQUIRE(result.get() == ERROR_SUCCESS);
}

/// Verifies a request fragmented into single bytes receives a valid response.
void test_pipe_server_accepts_fragmented_request()
{
	mcd::runtime::PipeServer server("test-profile");
	auto result = std::async(std::launch::async, [&server] {
		return server.run();
	});
	const HANDLE pipe = connect_client(
		std::chrono::steady_clock::now() + std::chrono::seconds(2));

	const auto request = mcd::protocol::encode({
		.kind = mcd::protocol::MessageKind::status_request,
		.payload = {},
	});
	for(const std::byte value : request)
	{
		write_all(pipe, std::span {&value, 1U});
	}

	auto response_bytes = std::async(std::launch::async, [pipe] {
		return read_response(pipe);
	});
	if(response_bytes.wait_for(std::chrono::seconds(2)) != std::future_status::ready)
	{
		server.request_stop();
		CloseHandle(pipe);
		const bool server_ready =
			result.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
		const bool response_ready =
			response_bytes.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
		REQUIRE(server_ready);
		REQUIRE(response_ready);
		fail("fragmented response deadline expired");
	}
	std::vector<std::byte> received_bytes;
	try
	{
		received_bytes = response_bytes.get();
	}
	catch(...)
	{
		server.request_stop();
		(void)result.wait_for(std::chrono::seconds(2));
		CloseHandle(pipe);
		throw;
	}
	const auto response = mcd::protocol::decode(received_bytes);
	REQUIRE(response.has_value());
	REQUIRE(response->kind == mcd::protocol::MessageKind::status_response);
	REQUIRE(!response->payload.empty());

	CloseHandle(pipe);
	server.request_stop();
	REQUIRE(result.wait_for(std::chrono::seconds(2)) == std::future_status::ready);
	REQUIRE(result.get() == ERROR_SUCCESS);
}

/// Verifies bad protocol magic is rejected by disconnecting the client.
void test_pipe_server_rejects_malformed_frame()
{
	mcd::runtime::PipeServer server("test-profile");
	auto result = std::async(std::launch::async, [&server] {
		return server.run();
	});
	const HANDLE pipe = connect_client(
		std::chrono::steady_clock::now() + std::chrono::seconds(2));

	auto request = mcd::protocol::encode({
		.kind = mcd::protocol::MessageKind::status_request,
		.payload = {},
	});
	request[0] = std::byte {'X'};
	write_all(pipe, request);
	wait_for_disconnect(
		pipe,
		std::chrono::steady_clock::now() + std::chrono::seconds(2));

	CloseHandle(pipe);
	server.request_stop();
	REQUIRE(result.wait_for(std::chrono::seconds(2)) == std::future_status::ready);
	REQUIRE(result.get() == ERROR_SUCCESS);
}

/// Verifies a malformed disconnected client cannot prevent a later valid session.
void test_pipe_server_recovers_after_malformed_disconnect()
{
	mcd::runtime::PipeServer server("test-profile");
	auto result = std::async(std::launch::async, [&server] {
		return server.run();
	});
	const auto deadline =
		std::chrono::steady_clock::now() + std::chrono::seconds(2);
	const HANDLE malformed_client = connect_client(deadline);
	const std::byte fragment {'M'};
	write_all(malformed_client, std::span {&fragment, 1U});
	CloseHandle(malformed_client);

	const HANDLE valid_client = connect_client(deadline);
	const auto request = mcd::protocol::encode({
		.kind = mcd::protocol::MessageKind::status_request,
		.payload = {},
	});
	write_all(valid_client, request);
	const auto response = mcd::protocol::decode(read_response(valid_client));
	REQUIRE(response.has_value());
	REQUIRE(response->kind == mcd::protocol::MessageKind::status_response);
	REQUIRE(!response->payload.empty());

	CloseHandle(valid_client);
	server.request_stop();
	REQUIRE(result.wait_for(std::chrono::seconds(2)) == std::future_status::ready);
	REQUIRE(result.get() == ERROR_SUCCESS);
}

/// Verifies oversized framing is rejected before a payload is read.
void test_pipe_server_rejects_oversized_frame()
{
	mcd::runtime::PipeServer server("test-profile");
	auto result = std::async(std::launch::async, [&server] {
		return server.run();
	});
	const HANDLE pipe = connect_client(
		std::chrono::steady_clock::now() + std::chrono::seconds(2));

	auto request = mcd::protocol::encode({
		.kind = mcd::protocol::MessageKind::status_request,
		.payload = {},
	});
	const std::uint32_t oversized =
		static_cast<std::uint32_t>(mcd::protocol::maximum_payload_size + 1U);
	request[7] = static_cast<std::byte>(oversized & 0xFFU);
	request[8] = static_cast<std::byte>((oversized >> 8U) & 0xFFU);
	request[9] = static_cast<std::byte>((oversized >> 16U) & 0xFFU);
	request[10] = static_cast<std::byte>((oversized >> 24U) & 0xFFU);
	write_all(pipe, request);
	wait_for_disconnect(
		pipe,
		std::chrono::steady_clock::now() + std::chrono::seconds(2));

	CloseHandle(pipe);
	server.request_stop();
	REQUIRE(result.wait_for(std::chrono::seconds(2)) == std::future_status::ready);
	REQUIRE(result.get() == ERROR_SUCCESS);
}

/// Verifies shutdown cancels a server blocked on a connected partial request.
void test_pipe_server_stops_while_connected()
{
	mcd::runtime::PipeServer server("test-profile");
	auto result = std::async(std::launch::async, [&server] {
		return server.run();
	});
	const HANDLE pipe = connect_client(
		std::chrono::steady_clock::now() + std::chrono::seconds(2));
	const std::byte fragment {'M'};
	write_all(pipe, std::span {&fragment, 1U});

	server.request_stop();
	REQUIRE(result.wait_for(std::chrono::seconds(2)) == std::future_status::ready);
	REQUIRE(result.get() == ERROR_SUCCESS);
	CloseHandle(pipe);
}

/// Verifies the pipe descriptor owns explicit owner/group SIDs and one logon-SID ACE.
void test_pipe_security_targets_logon_sid()
{
	const auto descriptor = mcd::runtime::detail::build_pipe_security_descriptor();
	REQUIRE(!descriptor.empty());

	PSID owner = nullptr;
	PSID group = nullptr;
	PACL dacl = nullptr;
	BOOL owner_defaulted = TRUE;
	BOOL group_defaulted = TRUE;
	BOOL dacl_present = FALSE;
	BOOL dacl_defaulted = TRUE;
	auto* security_descriptor =
		reinterpret_cast<PSECURITY_DESCRIPTOR>(const_cast<std::byte*>(descriptor.data()));
	REQUIRE(GetSecurityDescriptorOwner(
		security_descriptor,
		&owner,
		&owner_defaulted));
	REQUIRE(GetSecurityDescriptorGroup(
		security_descriptor,
		&group,
		&group_defaulted));
	REQUIRE(GetSecurityDescriptorDacl(
		security_descriptor,
		&dacl_present,
		&dacl,
		&dacl_defaulted));
	REQUIRE(owner != nullptr);
	REQUIRE(group != nullptr);
	REQUIRE(!owner_defaulted);
	REQUIRE(!group_defaulted);
	REQUIRE(dacl_present);
	REQUIRE(dacl != nullptr);
	REQUIRE(dacl->AceCount == 1U);

	void* raw_ace = nullptr;
	REQUIRE(GetAce(dacl, 0U, &raw_ace));
	const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw_ace);
	REQUIRE(ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE);
	REQUIRE((ace->Mask & (WRITE_DAC | WRITE_OWNER | DELETE)) == 0U);

	HANDLE raw_token = nullptr;
	REQUIRE(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token));
	const auto groups = token_information(raw_token, TokenGroups);
	const auto owner_information = token_information(raw_token, TokenOwner);
	const auto primary_group_information =
		token_information(raw_token, TokenPrimaryGroup);
	CloseHandle(raw_token);
	REQUIRE(EqualSid(
		const_cast<DWORD*>(&ace->SidStart),
		current_logon_sid(groups)));
	const auto* token_owner =
		reinterpret_cast<const TOKEN_OWNER*>(owner_information.data());
	const auto* token_primary_group =
		reinterpret_cast<const TOKEN_PRIMARY_GROUP*>(primary_group_information.data());
	REQUIRE(EqualSid(owner, token_owner->Owner));
	REQUIRE(EqualSid(group, token_primary_group->PrimaryGroup));
}

/// Verifies a captured operation failure survives later last-error changes.
void test_io_failure_preserves_original_error()
{
	const auto result = mcd::runtime::detail::io_failure(ERROR_ACCESS_DENIED);
	SetLastError(ERROR_INVALID_HANDLE);
	REQUIRE(result.status == mcd::runtime::detail::IoStatus::failed);
	REQUIRE(result.error == ERROR_ACCESS_DENIED);
}

/// Verifies successful cancellation resolves an aborted operation as stopped.
void test_cancelled_operation_reports_stopped()
{
	const auto result = mcd::runtime::detail::resolve_cancellation(
		TRUE,
		ERROR_SUCCESS,
		WAIT_OBJECT_0,
		ERROR_SUCCESS,
		FALSE,
		ERROR_OPERATION_ABORTED);
	REQUIRE(result.status == mcd::runtime::detail::IoStatus::stopped);
	REQUIRE(result.error == ERROR_OPERATION_ABORTED);
	REQUIRE(!result.operation_pending);
}

/// Verifies ERROR_NOT_FOUND is accepted only after resolving the completion race.
void test_cancel_not_found_resolves_completion()
{
	const auto result = mcd::runtime::detail::resolve_cancellation(
		FALSE,
		ERROR_NOT_FOUND,
		WAIT_OBJECT_0,
		ERROR_SUCCESS,
		TRUE,
		ERROR_SUCCESS);
	REQUIRE(result.status == mcd::runtime::detail::IoStatus::success);
	REQUIRE(result.error == ERROR_SUCCESS);
	REQUIRE(!result.operation_pending);
}

/// Verifies non-race cancellation failures retain their originating error.
void test_cancel_failure_preserves_error()
{
	const auto result = mcd::runtime::detail::resolve_cancellation(
		FALSE,
		ERROR_ACCESS_DENIED,
		WAIT_OBJECT_0,
		ERROR_SUCCESS,
		FALSE,
		ERROR_OPERATION_ABORTED);
	REQUIRE(result.status == mcd::runtime::detail::IoStatus::failed);
	REQUIRE(result.error == ERROR_ACCESS_DENIED);
	REQUIRE(!result.operation_pending);
}

/// Verifies bounded cancellation timeout retains pending-operation ownership.
void test_cancel_timeout_retains_pending_operation()
{
	const auto result = mcd::runtime::detail::resolve_cancellation(
		TRUE,
		ERROR_SUCCESS,
		WAIT_TIMEOUT,
		ERROR_SUCCESS,
		FALSE,
		ERROR_IO_INCOMPLETE);
	REQUIRE(result.status == mcd::runtime::detail::IoStatus::failed);
	REQUIRE(result.error == ERROR_TIMEOUT);
	REQUIRE(result.operation_pending);

	const auto failed_cancel = mcd::runtime::detail::resolve_cancellation(
		FALSE,
		ERROR_ACCESS_DENIED,
		WAIT_TIMEOUT,
		ERROR_SUCCESS,
		FALSE,
		ERROR_IO_INCOMPLETE);
	REQUIRE(failed_cancel.error == ERROR_ACCESS_DENIED);
	REQUIRE(failed_cancel.operation_pending);
}

/// Verifies a signaled but incomplete result retains operation storage.
void test_signaled_incomplete_result_remains_pending()
{
	const auto result = mcd::runtime::detail::resolve_cancellation(
		FALSE,
		ERROR_NOT_FOUND,
		WAIT_OBJECT_0,
		ERROR_SUCCESS,
		FALSE,
		ERROR_IO_INCOMPLETE);
	REQUIRE(result.status == mcd::runtime::detail::IoStatus::failed);
	REQUIRE(result.error == ERROR_IO_INCOMPLETE);
	REQUIRE(result.operation_pending);
}

/// Runs one named test while reporting its diagnostic boundary.
void run_test(const std::string_view name, void (*test)())
{
	std::cout << "RUN " << name << '\n';
	try
	{
		test();
	}
	catch(const std::exception& error)
	{
		std::cout << "FAIL " << name << ": " << error.what() << '\n';
		throw;
	}
	std::cout << "PASS " << name << '\n';
}
}

/// Runs the host-independent runtime lifecycle regression tests.
int main()
{
	std::cout << std::unitbuf;
	run_test("runtime rejects unknown build", &test_runtime_rejects_unknown_build);
	run_test("runtime reaches ready once", &test_runtime_reaches_ready_once);
	run_test("ready runtime stops cleanly", &test_ready_runtime_stops_cleanly);
	run_test("failed runtime unwinds", &test_failed_runtime_unwinds);
	run_test("pipe server stops while waiting", &test_pipe_server_stops_while_waiting);
	run_test("pipe server accepts fragmented request", &test_pipe_server_accepts_fragmented_request);
	run_test("pipe server rejects malformed frame", &test_pipe_server_rejects_malformed_frame);
	run_test(
		"pipe server recovers after malformed disconnect",
		&test_pipe_server_recovers_after_malformed_disconnect);
	run_test("pipe server rejects oversized frame", &test_pipe_server_rejects_oversized_frame);
	run_test("pipe server stops while connected", &test_pipe_server_stops_while_connected);
	run_test("pipe security targets logon SID", &test_pipe_security_targets_logon_sid);
	run_test("I/O failure preserves original error", &test_io_failure_preserves_original_error);
	run_test("cancelled operation reports stopped", &test_cancelled_operation_reports_stopped);
	run_test("cancel not found resolves completion", &test_cancel_not_found_resolves_completion);
	run_test("cancel failure preserves error", &test_cancel_failure_preserves_error);
	run_test("cancel timeout retains pending operation", &test_cancel_timeout_retains_pending_operation);
	run_test("signaled incomplete result remains pending", &test_signaled_incomplete_result_remains_pending);
	return 0;
}
