#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "mcd/protocol.hpp"

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

/// Names the encoded payload-size field offset within the fixed header.
inline constexpr std::size_t payload_size_offset = 7U;

/// Returns a deterministic binary payload of the requested size.
std::vector<std::byte> make_payload(const std::size_t size)
{
	std::vector<std::byte> payload(size);
	for(std::size_t index = 0; index < payload.size(); ++index)
	{
		payload[index] = static_cast<std::byte>(static_cast<unsigned char>(index & 0xFFU));
	}

	return payload;
}

/// Returns a byte vector copy of the provided UTF-8 text payload.
std::vector<std::byte> payload_bytes(const std::string_view text)
{
	const auto chars = std::span {text.data(), text.size()};
	const auto bytes = std::as_bytes(chars);
	return std::vector<std::byte>(bytes.begin(), bytes.end());
}

/// Decodes little-endian 32-bit integers from a message header.
std::uint32_t read_u32(const std::span<const std::byte> bytes, const std::size_t offset)
{
	return static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 0])) |
		(static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 1])) << 8U) |
		(static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 2])) << 16U) |
		(static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 3])) << 24U);
}

/// Encodes little-endian 32-bit integers into a mutable message buffer.
void write_u32(std::span<std::byte> bytes, const std::size_t offset, const std::uint32_t value)
{
	bytes[offset + 0] = static_cast<std::byte>(value & 0xFFU);
	bytes[offset + 1] = static_cast<std::byte>((value >> 8U) & 0xFFU);
	bytes[offset + 2] = static_cast<std::byte>((value >> 16U) & 0xFFU);
	bytes[offset + 3] = static_cast<std::byte>((value >> 24U) & 0xFFU);
}

/// Verifies that a known frame encodes to the exact expected wire bytes.
void test_known_frame_encoding()
{
	const mcd::protocol::Message response {
		.kind = mcd::protocol::MessageKind::status_response,
		.payload = payload_bytes("OK"),
	};

	const auto bytes = mcd::protocol::encode(response);
	const std::vector<std::byte> expected {
		std::byte {0x4D},
		std::byte {0x43},
		std::byte {0x44},
		std::byte {0x52},
		std::byte {0x01},
		std::byte {0x00},
		std::byte {0x02},
		std::byte {0x02},
		std::byte {0x00},
		std::byte {0x00},
		std::byte {0x00},
		std::byte {0x4F},
		std::byte {0x4B},
	};

	REQUIRE(bytes == expected);
}

/// Verifies that a status request survives a complete wire round trip.
void test_status_round_trip()
{
	const mcd::protocol::Message request {
		.kind = mcd::protocol::MessageKind::status_request,
		.payload = {},
	};

	const auto bytes = mcd::protocol::encode(request);
	const auto decoded = mcd::protocol::decode(bytes);
	REQUIRE(decoded.has_value());
	REQUIRE(decoded->kind == request.kind);
	REQUIRE(decoded->payload.empty());
}

/// Verifies that a ready status response round-trips its JSON payload unchanged.
void test_ready_response_round_trip()
{
	constexpr std::string_view payload =
		R"({"state":"ready","runtime_version":"0.1.0","profile_id":"steam-2026-10-19","process_id":4242})";

	const mcd::protocol::Message response {
		.kind = mcd::protocol::MessageKind::status_response,
		.payload = payload_bytes(payload),
	};

	const auto bytes = mcd::protocol::encode(response);
	const auto decoded = mcd::protocol::decode(bytes);
	REQUIRE(decoded.has_value());
	REQUIRE(decoded->kind == response.kind);
	REQUIRE(decoded->payload == response.payload);
}

/// Verifies that the maximum permitted 64 KiB payload is accepted.
void test_accepts_maximum_payload()
{
	const mcd::protocol::Message response {
		.kind = mcd::protocol::MessageKind::status_response,
		.payload = make_payload(mcd::protocol::maximum_payload_size),
	};

	const auto bytes = mcd::protocol::encode(response);
	REQUIRE(bytes.size() == mcd::protocol::header_size + mcd::protocol::maximum_payload_size);

	const auto decoded = mcd::protocol::decode(bytes);
	REQUIRE(decoded.has_value());
	REQUIRE(decoded->kind == response.kind);
	REQUIRE(decoded->payload == response.payload);
}

/// Verifies that incomplete headers are rejected before field decoding.
void test_rejects_truncated_header()
{
	auto bytes = mcd::protocol::encode(
		{
			.kind = mcd::protocol::MessageKind::status_request,
			.payload = {},
		});
	bytes.resize(mcd::protocol::header_size - 1U);

	const auto decoded = mcd::protocol::decode(bytes);
	REQUIRE(!decoded.has_value());
	REQUIRE(decoded.error() == mcd::protocol::ProtocolError::truncated_header);
}

/// Verifies that frames with an unexpected magic signature are rejected.
void test_rejects_bad_magic()
{
	const mcd::protocol::Message request {
		.kind = mcd::protocol::MessageKind::status_request,
		.payload = {},
	};

	auto bytes = mcd::protocol::encode(request);
	bytes[0] = std::byte {'X'};

	const auto decoded = mcd::protocol::decode(bytes);
	REQUIRE(!decoded.has_value());
	REQUIRE(decoded.error() == mcd::protocol::ProtocolError::bad_magic);
}

/// Verifies that frames from unsupported protocol versions are rejected.
void test_rejects_unsupported_version()
{
	auto bytes = mcd::protocol::encode(
		{
			.kind = mcd::protocol::MessageKind::status_request,
			.payload = {},
		});
	bytes[4] = std::byte {0x02};
	bytes[5] = std::byte {0x00};

	const auto decoded = mcd::protocol::decode(bytes);
	REQUIRE(!decoded.has_value());
	REQUIRE(decoded.error() == mcd::protocol::ProtocolError::unsupported_version);
}

/// Verifies that unsupported message-kind bytes are rejected.
void test_rejects_invalid_message_kind()
{
	auto bytes = mcd::protocol::encode(
		{
			.kind = mcd::protocol::MessageKind::status_request,
			.payload = {},
		});
	bytes[6] = std::byte {0x7F};

	const auto decoded = mcd::protocol::decode(bytes);
	REQUIRE(!decoded.has_value());
	REQUIRE(decoded.error() == mcd::protocol::ProtocolError::invalid_message_kind);
}

/// Verifies that frames with mismatched payload lengths are rejected.
void test_rejects_mismatched_payload_length()
{
	const mcd::protocol::Message response {
		.kind = mcd::protocol::MessageKind::status_response,
		.payload = payload_bytes(R"({"state":"ready"})"),
	};

	auto bytes = mcd::protocol::encode(response);
	const auto declared_size = read_u32(bytes, payload_size_offset);
	write_u32(bytes, payload_size_offset, declared_size + 1U);

	const auto decoded = mcd::protocol::decode(bytes);
	REQUIRE(!decoded.has_value());
	REQUIRE(decoded.error() == mcd::protocol::ProtocolError::payload_length_mismatch);
}

/// Verifies that frames larger than the bounded maximum are rejected before allocation.
void test_rejects_oversized_payload()
{
	std::vector<std::byte> bytes(
		mcd::protocol::header_size + mcd::protocol::maximum_payload_size + 1U,
		std::byte {0x00});
	bytes[0] = std::byte {'M'};
	bytes[1] = std::byte {'C'};
	bytes[2] = std::byte {'D'};
	bytes[3] = std::byte {'R'};
	bytes[4] = std::byte {0x01};
	bytes[5] = std::byte {0x00};
	bytes[6] = std::byte {static_cast<unsigned char>(mcd::protocol::MessageKind::status_response)};
	write_u32(
		bytes,
		payload_size_offset,
		static_cast<std::uint32_t>(mcd::protocol::maximum_payload_size + 1U));

	const auto decoded = mcd::protocol::decode(bytes);
	REQUIRE(!decoded.has_value());
	REQUIRE(decoded.error() == mcd::protocol::ProtocolError::payload_too_large);
}
}

/// Runs the protocol regression tests.
int main()
{
	test_known_frame_encoding();
	test_status_round_trip();
	test_ready_response_round_trip();
	test_accepts_maximum_payload();
	test_rejects_truncated_header();
	test_rejects_bad_magic();
	test_rejects_unsupported_version();
	test_rejects_invalid_message_kind();
	test_rejects_mismatched_payload_length();
	test_rejects_oversized_payload();
	return 0;
}
