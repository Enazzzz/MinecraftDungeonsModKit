#include "mcd/protocol.hpp"

#include <array>
#include <stdexcept>

#include "mcd/wire.hpp"

namespace
{
/// Returns the fixed protocol magic bytes.
constexpr std::array<std::byte, 4> protocol_magic()
{
	return {
		std::byte {'M'},
		std::byte {'C'},
		std::byte {'D'},
		std::byte {'R'},
	};
}

/// Returns whether one raw message kind byte names a supported message.
constexpr bool is_valid_message_kind(const std::uint8_t value)
{
	return value == static_cast<std::uint8_t>(mcd::protocol::MessageKind::status_request) ||
		value == static_cast<std::uint8_t>(mcd::protocol::MessageKind::status_response) ||
		value == static_cast<std::uint8_t>(mcd::protocol::MessageKind::objects_request) ||
		value == static_cast<std::uint8_t>(mcd::protocol::MessageKind::objects_response);
}

/// Converts one raw message kind byte into its typed protocol enum.
constexpr mcd::protocol::MessageKind to_message_kind(const std::uint8_t value)
{
	return static_cast<mcd::protocol::MessageKind>(value);
}
}

namespace mcd::protocol
{
/// Encodes one protocol message into the fixed little-endian wire format.
std::vector<std::byte> encode(const Message& message)
{
	if(message.payload.size() > maximum_payload_size)
	{
		throw std::length_error("Protocol payload exceeds 64 KiB.");
	}

	const auto raw_kind = static_cast<std::uint8_t>(message.kind);
	if(!is_valid_message_kind(raw_kind))
	{
		throw std::invalid_argument("Protocol message kind is not supported.");
	}

	std::vector<std::byte> bytes;
	bytes.reserve(header_size + message.payload.size());

	for(const std::byte value : protocol_magic())
	{
		bytes.push_back(value);
	}

	wire::append_u16_le(bytes, current_version);
	wire::append_u8(bytes, raw_kind);
	wire::append_u32_le(bytes, static_cast<std::uint32_t>(message.payload.size()));
	bytes.insert(bytes.end(), message.payload.begin(), message.payload.end());
	return bytes;
}

/// Decodes one complete wire frame after validating its bounded header and payload.
std::expected<Message, ProtocolError> decode(const std::span<const std::byte> bytes)
{
	if(bytes.size() < header_size)
	{
		return std::unexpected(ProtocolError::truncated_header);
	}

	constexpr auto magic = protocol_magic();
	if(bytes[0] != magic[0] || bytes[1] != magic[1] || bytes[2] != magic[2] || bytes[3] != magic[3])
	{
		return std::unexpected(ProtocolError::bad_magic);
	}

	if(wire::read_u16_le(bytes, 4U) != current_version)
	{
		return std::unexpected(ProtocolError::unsupported_version);
	}

	const std::uint8_t raw_kind = wire::read_u8(bytes, 6U);
	if(!is_valid_message_kind(raw_kind))
	{
		return std::unexpected(ProtocolError::invalid_message_kind);
	}

	const std::uint32_t payload_size = wire::read_u32_le(bytes, 7U);
	if(payload_size > maximum_payload_size)
	{
		return std::unexpected(ProtocolError::payload_too_large);
	}

	if(bytes.size() != header_size + payload_size)
	{
		return std::unexpected(ProtocolError::payload_length_mismatch);
	}

	Message message {
		.kind = to_message_kind(raw_kind),
		.payload = {},
	};
	message.payload.reserve(payload_size);
	const auto payload = bytes.subspan(header_size, payload_size);
	message.payload.insert(message.payload.end(), payload.begin(), payload.end());
	return message;
}
}
