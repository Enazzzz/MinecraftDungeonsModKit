#include "mcd/x64_prologue.hpp"

namespace
{
/// Returns the byte length of one supported non-relative instruction, including its offset.
std::optional<std::size_t> instruction_length(const std::span<const std::byte> code)
{
	if(code.empty())
	{
		return std::nullopt;
	}

	std::size_t index = 0U;
	bool rex_w = false;
	const auto lead = std::to_integer<unsigned>(code[0]);
	if(lead >= 0x40U && lead <= 0x4FU)
	{
		rex_w = (lead & 0x08U) != 0U;
		index = 1U;
		if(index >= code.size())
		{
			return std::nullopt;
		}
	}

	const auto opcode = std::to_integer<unsigned>(code[index]);
	++index;
	if((opcode >= 0x50U && opcode <= 0x5FU) || opcode == 0x90U)
	{
		return index;
	}

	auto modrm_end = [&]() -> std::optional<std::size_t> {
		if(index >= code.size())
		{
			return std::nullopt;
		}
		const auto modrm = std::to_integer<unsigned>(code[index]);
		std::size_t extra = 1U;
		const auto mod = modrm >> 6U;
		const auto rm = modrm & 7U;
		const bool sib = mod != 3U && rm == 4U;
		if(sib)
		{
			++extra;
		}
		if(mod == 1U)
		{
			extra += 1U;
		}
		else if(mod == 2U)
		{
			extra += 4U;
		}
		else if(mod == 0U && rm == 5U)
		{
			return std::nullopt;
		}
		else if(mod == 0U && sib)
		{
			if(index + 1U >= code.size())
			{
				return std::nullopt;
			}
			const auto sib_byte = std::to_integer<unsigned>(code[index + 1U]);
			if((sib_byte & 7U) == 5U)
			{
				extra += 4U;
			}
		}
		if(index + extra > code.size())
		{
			return std::nullopt;
		}
		return index + extra;
	};

	if(opcode == 0x89U || opcode == 0x8BU || opcode == 0x8DU || opcode == 0x01U ||
		opcode == 0x03U || opcode == 0x29U || opcode == 0x2BU || opcode == 0x31U ||
		opcode == 0x33U || opcode == 0x85U)
	{
		return modrm_end();
	}
	if(opcode == 0x83U)
	{
		const auto end = modrm_end();
		if(!end || *end + 1U > code.size())
		{
			return std::nullopt;
		}
		return *end + 1U;
	}
	if(opcode == 0x81U)
	{
		const auto end = modrm_end();
		if(!end || *end + 4U > code.size())
		{
			return std::nullopt;
		}
		return *end + 4U;
	}
	if(opcode >= 0xB8U && opcode <= 0xBFU)
	{
		const auto immediate = rex_w ? 8U : 4U;
		if(index + immediate > code.size())
		{
			return std::nullopt;
		}
		return index + immediate;
	}
	return std::nullopt;
}
}

namespace mcd
{
/// Returns how many leading bytes form whole instructions covering at least `minimum`.
std::optional<std::size_t> steal_size(
	const std::span<const std::byte> code,
	const std::size_t minimum)
{
	std::size_t offset = 0U;
	while(offset < minimum)
	{
		const auto length = instruction_length(code.subspan(offset));
		if(!length || *length == 0U)
		{
			return std::nullopt;
		}
		offset += *length;
		if(offset > code.size() || offset > 32U)
		{
			return std::nullopt;
		}
	}
	return offset;
}
}
