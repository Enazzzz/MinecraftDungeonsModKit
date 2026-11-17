#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace mcd
{
/// Returns how many leading bytes form whole instructions covering at least `minimum`.
/// Rip-relative instructions are rejected so the bytes can be relocated into a trampoline.
[[nodiscard]] std::optional<std::size_t> steal_size(
	std::span<const std::byte> code,
	std::size_t minimum);
}
