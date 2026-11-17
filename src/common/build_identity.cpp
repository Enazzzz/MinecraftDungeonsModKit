#include "mcd/build_identity.hpp"

namespace
{
/// Returns the supported Steam build profile.
constexpr mcd::BuildProfile supported_profile()
{
	return mcd::BuildProfile {
		.id = "steam-2026-10-19",
		.image_size = 37'814'288,
		.sha256 =
			{
				std::byte {0x6A}, std::byte {0x48}, std::byte {0x47}, std::byte {0x14},
				std::byte {0x23}, std::byte {0xB4}, std::byte {0x1C}, std::byte {0xDC},
				std::byte {0xDD}, std::byte {0x4F}, std::byte {0x03}, std::byte {0x22},
				std::byte {0x56}, std::byte {0x0D}, std::byte {0xCA}, std::byte {0xFA},
				std::byte {0xE0}, std::byte {0xF4}, std::byte {0x33}, std::byte {0xF3},
				std::byte {0xBC}, std::byte {0x30}, std::byte {0x72}, std::byte {0x1F},
				std::byte {0xAE}, std::byte {0x86}, std::byte {0x15}, std::byte {0x64},
				std::byte {0xA4}, std::byte {0xF5}, std::byte {0xCC}, std::byte {0x73},
			},
		.names_global_rva = 0x4692538U,
		.object_array_rva = 0x4696838U,
	};
}

/// Converts a single hexadecimal digit into its nibble value.
constexpr int hex_value(const char ch)
{
	if(ch >= '0' && ch <= '9')
	{
		return ch - '0';
	}

	if(ch >= 'A' && ch <= 'F')
	{
		return 10 + (ch - 'A');
	}

	if(ch >= 'a' && ch <= 'f')
	{
		return 10 + (ch - 'a');
	}

	return -1;
}
}

namespace mcd
{
/// Parses exactly 64 hexadecimal SHA-256 characters.
std::optional<Sha256Digest> parse_sha256(const std::string_view text)
{
	if(text.size() != 64)
	{
		return std::nullopt;
	}

	Sha256Digest digest {};
	for(std::size_t index = 0; index < digest.size(); ++index)
	{
		const int high = hex_value(text[(index * 2) + 0]);
		const int low = hex_value(text[(index * 2) + 1]);
		if(high < 0 || low < 0)
		{
			return std::nullopt;
		}

		digest[index] = static_cast<std::byte>((high << 4) | low);
	}

	return digest;
}

/// Returns the profile matching both executable size and digest.
std::optional<BuildProfile> identify_build(
	const std::uint64_t image_size,
	const Sha256Digest& digest)
{
	constexpr BuildProfile profile = supported_profile();
	if(image_size == profile.image_size && digest == profile.sha256)
	{
		return profile;
	}

	return std::nullopt;
}

/// Returns the supported profile with the supplied id.
std::optional<BuildProfile> profile_for_id(const std::string_view id)
{
	constexpr BuildProfile profile = supported_profile();
	if(id == profile.id)
	{
		return profile;
	}
	return std::nullopt;
}
}
