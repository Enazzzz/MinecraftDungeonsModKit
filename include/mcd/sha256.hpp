#pragma once

#include <array>
#include <cstddef>
#include <expected>
#include <filesystem>
#include <optional>
#include <string_view>
#include <system_error>

namespace mcd
{
using Sha256Digest = std::array<std::byte, 32>;

/// Parses exactly 64 hexadecimal SHA-256 characters.
[[nodiscard]] std::optional<Sha256Digest> parse_sha256(std::string_view text);

/// Hashes a file through the Windows BCrypt SHA-256 provider.
[[nodiscard]] std::expected<Sha256Digest, std::error_code> sha256_file(
	const std::filesystem::path& path);
}
