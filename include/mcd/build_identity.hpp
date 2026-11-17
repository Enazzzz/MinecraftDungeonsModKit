#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

#include "mcd/sha256.hpp"

namespace mcd
{
/// Describes one exact executable fingerprint that the runtime supports.
struct BuildProfile
{
	std::string_view id;
	std::uint64_t image_size;
	Sha256Digest sha256;
	std::uintptr_t names_global_rva;
	std::uintptr_t object_array_rva;
};

/// Returns the profile matching both executable size and digest.
[[nodiscard]] std::optional<BuildProfile> identify_build(
	std::uint64_t image_size,
	const Sha256Digest& digest);

/// Returns the supported profile with the supplied id.
[[nodiscard]] std::optional<BuildProfile> profile_for_id(std::string_view id);
}
