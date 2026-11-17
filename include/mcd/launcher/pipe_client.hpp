#pragma once

#include <expected>
#include <string>

#include "mcd/protocol.hpp"

#include <windows.h>

namespace mcd::launcher
{
/// Names bounded status-client failures.
enum class PipeClientError
{
	invalid_process_id,
	open_failed,
	server_identity_mismatch,
	request_failed,
	timeout,
	response_failed,
	protocol_failed,
	unexpected_response,
};

/// Carries one status-client failure category and its originating Win32 error.
struct PipeClientFailure
{
	PipeClientError error;
	DWORD win32_error;
};

namespace detail
{
/// Returns whether a connected pipe server is the exact requested process.
[[nodiscard]] bool server_process_matches(
	DWORD requested_process_id,
	DWORD server_process_id) noexcept;

/// Queries one runtime pipe with a caller-supplied bounded timeout.
[[nodiscard]] std::expected<std::string, PipeClientFailure> query_status(
	DWORD process_id,
	DWORD timeout_ms,
	mcd::protocol::MessageKind request = mcd::protocol::MessageKind::status_request,
	mcd::protocol::MessageKind response = mcd::protocol::MessageKind::status_response);
}

/// Queries one runtime status pipe and returns its validated JSON payload.
[[nodiscard]] std::expected<std::string, PipeClientFailure> query_status(DWORD process_id);

/// Queries the runtime for its validated Unreal object-array report.
[[nodiscard]] std::expected<std::string, PipeClientFailure> query_objects(DWORD process_id);

/// Returns a stable diagnostic name for one status-client failure.
[[nodiscard]] std::string pipe_error_message(const PipeClientFailure& failure);
}
