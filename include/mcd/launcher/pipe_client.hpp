#pragma once

#include <expected>
#include <string>

#include <windows.h>

namespace mcd::launcher
{
/// Names bounded status-client failures.
enum class PipeClientError
{
	invalid_process_id,
	open_failed,
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

/// Queries one runtime status pipe and returns its validated JSON payload.
[[nodiscard]] std::expected<std::string, PipeClientFailure> query_status(DWORD process_id);

/// Returns a stable diagnostic name for one status-client failure.
[[nodiscard]] std::string pipe_error_message(const PipeClientFailure& failure);
}
