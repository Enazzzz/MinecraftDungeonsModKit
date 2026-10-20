#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace mcd::wire
{
/// Appends one raw byte to a serialized wire buffer.
inline void append_u8(std::vector<std::byte>& bytes, const std::uint8_t value)
{
	bytes.push_back(static_cast<std::byte>(value));
}

/// Appends one little-endian 16-bit integer to a serialized wire buffer.
inline void append_u16_le(std::vector<std::byte>& bytes, const std::uint16_t value)
{
	bytes.push_back(static_cast<std::byte>(value & 0xFFU));
	bytes.push_back(static_cast<std::byte>((value >> 8U) & 0xFFU));
}

/// Appends one little-endian 32-bit integer to a serialized wire buffer.
inline void append_u32_le(std::vector<std::byte>& bytes, const std::uint32_t value)
{
	bytes.push_back(static_cast<std::byte>(value & 0xFFU));
	bytes.push_back(static_cast<std::byte>((value >> 8U) & 0xFFU));
	bytes.push_back(static_cast<std::byte>((value >> 16U) & 0xFFU));
	bytes.push_back(static_cast<std::byte>((value >> 24U) & 0xFFU));
}

/// Returns one raw byte from a serialized wire buffer.
[[nodiscard]] inline std::uint8_t read_u8(
	const std::span<const std::byte> bytes,
	const std::size_t offset)
{
	return std::to_integer<std::uint8_t>(bytes[offset]);
}

/// Returns one little-endian 16-bit integer from a serialized wire buffer.
[[nodiscard]] inline std::uint16_t read_u16_le(
	const std::span<const std::byte> bytes,
	const std::size_t offset)
{
	return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[offset + 0])) |
		static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[offset + 1]) << 8U);
}

/// Returns one little-endian 32-bit integer from a serialized wire buffer.
[[nodiscard]] inline std::uint32_t read_u32_le(
	const std::span<const std::byte> bytes,
	const std::size_t offset)
{
	return static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 0])) |
		(static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 1])) << 8U) |
		(static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 2])) << 16U) |
		(static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 3])) << 24U);
}
}
