#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

namespace mcd::protocol
{
/// Identifies the current protocol framing revision.
inline constexpr std::uint16_t current_version = 1U;

/// Defines the largest accepted wire payload in bytes.
inline constexpr std::size_t maximum_payload_size = 64U * 1024U;

/// Defines the fixed encoded header size in bytes.
inline constexpr std::size_t header_size = 11U;

/// Names the supported control message types.
enum class MessageKind : std::uint8_t
{
	status_request = 1U,
	status_response = 2U,
	objects_request = 3U,
	objects_response = 4U,
};

/// Names the reasons that a wire frame can be rejected.
enum class ProtocolError
{
	truncated_header,
	bad_magic,
	unsupported_version,
	invalid_message_kind,
	payload_too_large,
	payload_length_mismatch,
};

/// Stores one decoded or to-be-encoded protocol message.
struct Message
{
	MessageKind kind {};
	std::vector<std::byte> payload {};
};

/// Encodes one protocol message into the fixed little-endian wire format.
[[nodiscard]] std::vector<std::byte> encode(const Message& message);

/// Decodes one complete wire frame after validating its bounded header and payload.
[[nodiscard]] std::expected<Message, ProtocolError> decode(std::span<const std::byte> bytes);
}
