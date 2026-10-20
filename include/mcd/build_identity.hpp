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
};

/// Returns the profile matching both executable size and digest.
[[nodiscard]] std::optional<BuildProfile> identify_build(
	std::uint64_t image_size,
	const Sha256Digest& digest);
}
