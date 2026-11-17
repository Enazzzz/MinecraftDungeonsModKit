#include "mcd/pattern.hpp"

#include <charconv>

namespace
{
/// Parses one hexadecimal byte token.
std::optional<std::byte> parse_hex_byte(const std::string_view token)
{
	if(token.size() != 2U)
	{
		return std::nullopt;
	}
	unsigned int value = 0U;
	const auto result = std::from_chars(token.data(), token.data() + token.size(), value, 16);
	if(result.ec != std::errc {} || result.ptr != token.data() + token.size() || value > 0xFFU)
	{
		return std::nullopt;
	}
	return static_cast<std::byte>(value);
}
}

namespace mcd
{
/// Parses space-separated hex bytes and `?` or `??` wildcards.
std::optional<Pattern> parse_pattern(const std::string_view text)
{
	Pattern pattern;
	std::size_t cursor = 0U;
	while(cursor < text.size())
	{
		while(cursor < text.size() && text[cursor] == ' ')
		{
			++cursor;
		}
		if(cursor >= text.size())
		{
			break;
		}
		const std::size_t end = text.find(' ', cursor);
		const auto token = text.substr(cursor, end == std::string_view::npos ? text.size() - cursor : end - cursor);
		cursor = end == std::string_view::npos ? text.size() : end;
		if(token == "?" || token == "??")
		{
			pattern.atoms.emplace_back(std::nullopt);
			continue;
		}
		const auto byte = parse_hex_byte(token);
		if(!byte)
		{
			return std::nullopt;
		}
		pattern.atoms.push_back(byte);
	}
	if(pattern.atoms.empty())
	{
		return std::nullopt;
	}
	return pattern;
}

/// Finds the next pattern match at or after one offset.
std::optional<std::size_t> find_pattern(
	const std::span<const std::byte> bytes,
	const Pattern& pattern,
	const std::size_t start)
{
	if(pattern.atoms.empty() || bytes.size() < pattern.atoms.size() || start > bytes.size() - pattern.atoms.size())
	{
		return std::nullopt;
	}
	for(std::size_t offset = start; offset <= bytes.size() - pattern.atoms.size(); ++offset)
	{
		bool matched = true;
		for(std::size_t index = 0U; index < pattern.atoms.size(); ++index)
		{
			const auto& atom = pattern.atoms[index];
			if(atom && bytes[offset + index] != *atom)
			{
				matched = false;
				break;
			}
		}
		if(matched)
		{
			return offset;
		}
	}
	return std::nullopt;
}

/// Resolves an x64 RIP-relative displacement to an absolute address.
std::optional<std::uintptr_t> resolve_rip_relative(
	const std::uintptr_t instruction,
	const std::int32_t displacement,
	const std::size_t instruction_size)
{
	if(instruction_size == 0U || instruction_size > 15U)
	{
		return std::nullopt;
	}
	const auto next = instruction + instruction_size;
	if(displacement < 0 && next < static_cast<std::uintptr_t>(-static_cast<std::int64_t>(displacement)))
	{
		return std::nullopt;
	}
	return next + static_cast<std::uintptr_t>(static_cast<std::int64_t>(displacement));
}
}
