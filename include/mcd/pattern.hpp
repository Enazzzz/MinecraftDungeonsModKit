#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace mcd
{
/// Stores one masked byte pattern. An empty atom matches any byte.
struct Pattern
{
	std::vector<std::optional<std::byte>> atoms {};
};

/// Parses space-separated hex bytes and `?` or `??` wildcards.
[[nodiscard]] std::optional<Pattern> parse_pattern(std::string_view text);

/// Finds the next pattern match at or after one offset.
[[nodiscard]] std::optional<std::size_t> find_pattern(
	std::span<const std::byte> bytes,
	const Pattern& pattern,
	std::size_t start = 0U);

/// Resolves an x64 RIP-relative displacement to an absolute address.
[[nodiscard]] std::optional<std::uintptr_t> resolve_rip_relative(
	std::uintptr_t instruction,
	std::int32_t displacement,
	std::size_t instruction_size);
}
